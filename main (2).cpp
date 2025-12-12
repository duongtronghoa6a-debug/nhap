#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <random>
#include <limits>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <fstream>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Net/HTTPClientSession.h>
#include <Poco/Net/HTMLForm.h>
#include <Poco/Net/NetException.h>
#include <Poco/URI.h>
#include <Poco/StreamCopier.h>
#include <Poco/JSON/Parser.h>
#include <Poco/JSON/Object.h>
#include <Poco/JSON/Array.h>
#include <Poco/UUID.h>
#include <Poco/UUIDGenerator.h>

using namespace std;

string JWT_SECRET = []()
{ const char *env = getenv("JWT_SECRET"); return env ? string(env) : string("abcdefghijkmnopqrstuvwxyz"); }();

string sha256_hex(const string &in)
{
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)in.data(), in.size(), md);
    ostringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        ss << setw(2) << (int)md[i];
    return ss.str();
}

string hex_encode(const unsigned char *data, size_t len)
{
    ostringstream ss;
    ss << hex << setfill('0');
    for (size_t i = 0; i < len; ++i)
        ss << setw(2) << (int)data[i];
    return ss.str();
}

vector<unsigned char> hex_decode(const string &hex)
{
    vector<unsigned char> out;
    if (hex.size() % 2)
        return out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        string byte = hex.substr(i, 2);
        if (!isxdigit((unsigned char)byte[0]) || !isxdigit((unsigned char)byte[1]))
            return vector<unsigned char>();
        unsigned char v = (unsigned char)strtol(byte.c_str(), nullptr, 16);
        out.push_back(v);
    }
    return out;
}

string generate_salt_hex(size_t bytes = 16)
{
    vector<unsigned char> buf(bytes);
    if (RAND_bytes(buf.data(), (int)bytes) != 1)
        return string();
    return hex_encode(buf.data(), buf.size());
}

string pbkdf2_hash(const string &password, const string &salt_hex, int iterations = 100000, int dklen = 32)
{
    auto salt = hex_decode(salt_hex);
    if (salt.empty())
        return string();
    vector<unsigned char> out(dklen);
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(), salt.data(), (int)salt.size(), iterations, EVP_sha256(), dklen, out.data()))
        return string();
    return hex_encode(out.data(), out.size());
}

bool pbkdf2_verify(const string &password, const string &salt_hex, const string &hash_hex, int iterations = 100000, int dklen = 32)
{
    string computed = pbkdf2_hash(password, salt_hex, iterations, dklen);
    return !computed.empty() && (computed == hash_hex);
}

string openssl_base64_encode(const unsigned char *data, size_t len)
{
    if (!data || len == 0)
        return string();

    int out_len = 4 * ((int)((len + 2) / 3));
    string out;
    out.resize(out_len);
    int encoded = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(&out[0]), data, (int)len);
    if (encoded < 0)
        return string();
    out.resize(encoded);
    return out;
}

string base64url_encode(const string &s)
{
    string enc = openssl_base64_encode((const unsigned char *)s.data(), s.size());
    for (auto &c : enc)
    {
        if (c == '+')
            c = '-';
        else if (c == '/')
            c = '_';
    }
    while (!enc.empty() && enc.back() == '=')
        enc.pop_back();
    return enc;
}

string base64url_encode_bytes(const unsigned char *data, size_t len)
{
    string enc = openssl_base64_encode(data, len);
    for (auto &c : enc)
    {
        if (c == '+')
            c = '-';
        else if (c == '/')
            c = '_';
    }
    while (!enc.empty() && enc.back() == '=')
        enc.pop_back();
    return enc;
}

string openssl_base64_decode_to_string(const string &in)
{
    string s = in;
    for (auto &c : s)
    {
        if (c == '-')
            c = '+';
        else if (c == '_')
            c = '/';
    }
    while (s.size() % 4)
        s.push_back('=');
    vector<unsigned char> out;
    out.resize(3 * (s.size() / 4) + 4);
    int decoded = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char *>(s.data()), (int)s.size());
    if (decoded < 0)
        return string();
    int padding = 0;
    if (!s.empty() && s.back() == '=')
        padding++;
    if (s.size() > 1 && s[s.size() - 2] == '=')
        padding++;
    decoded -= padding;
    return string(reinterpret_cast<char *>(out.data()), decoded);
}

string base64url_decode_to_string(const string &in)
{
    return openssl_base64_decode_to_string(in);
}

string hmac_sha256(const string &key, const string &data)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    HMAC(EVP_sha256(), key.data(), (int)key.size(), (const unsigned char *)data.data(), (size_t)data.size(), md, &mdlen);
    return string((char *)md, mdlen);
}

string jwt_generate(const string &sub, const string &jti, int ttl_seconds = 3600)
{
    time_t now = time(nullptr);
    long iat = (long)now;
    long exp = (long)(now + ttl_seconds);
    Poco::JSON::Object header;
    header.set("alg", "HS256");
    header.set("typ", "JWT");
    ostringstream hs;
    header.stringify(hs);
    string h64 = base64url_encode(hs.str());

    Poco::JSON::Object payload;
    payload.set("sub", sub);
    payload.set("iat", iat);
    payload.set("exp", exp);
    payload.set("jti", jti);
    ostringstream ps;
    payload.stringify(ps);
    string p64 = base64url_encode(ps.str());
    string sig = hmac_sha256(JWT_SECRET, h64 + "." + p64);
    string sig64 = base64url_encode_bytes((const unsigned char *)sig.data(), sig.size());
    return h64 + "." + p64 + "." + sig64;
}

bool jwt_verify(const string &token, string &out_sub, string &out_jti)
{
    if (token.empty())
        return false;
    size_t p1 = token.find('.');
    if (p1 == string::npos)
        return false;
    size_t p2 = token.find('.', p1 + 1);
    if (p2 == string::npos)
        return false;
    string h64 = token.substr(0, p1);
    string p64 = token.substr(p1 + 1, p2 - p1 - 1);
    string s64 = token.substr(p2 + 1);
    string expected_bin = hmac_sha256(JWT_SECRET, h64 + "." + p64);
    string expected_sig64 = base64url_encode_bytes((const unsigned char *)expected_bin.data(), expected_bin.size());
    if (expected_sig64 != s64)
        return false;
    string payload = base64url_decode_to_string(p64);
    try
    {
        Poco::JSON::Parser parser;
        Poco::Dynamic::Var var = parser.parse(payload);
        Poco::JSON::Object::Ptr obj = var.extract<Poco::JSON::Object::Ptr>();
        if (obj->has("sub"))
            out_sub = obj->getValue<string>("sub");
        if (obj->has("exp"))
        {
            long exp = 0;
            try
            {
                exp = obj->getValue<long>("exp");
            }
            catch (...)
            {
                exp = (long)obj->getValue<double>("exp");
            }
            long now = (long)time(nullptr);
            if (now > exp)
                return false;
        }
        if (obj->has("jti"))
            out_jti = obj->getValue<string>("jti");
    }
    catch (...)
    {
        return false;
    }
    return true;
}

struct User
{
    std::string password_hash;
    std::string salt_hex;
    int iterations = 100000;
    std::string token;
    std::string token_jti;
    std::string user_public_key;
};
struct Note
{
    std::string owner;
    std::string content;
};

struct SharedNote
{
    std::string owner;
    std::string content;
    std::string public_key;
    std::string iv;
};

namespace
{
    std::map<std::string, User> g_users;
    std::map<std::string, Note> g_notes;
    std::map<std::string, std::string> g_shares;
    std::map<std::string, SharedNote> g_shared_notes;
    std::mutex g_mtx;
}

string generate_jti()
{
    Poco::UUID uuid = Poco::UUIDGenerator::defaultGenerator().createRandom();
    return uuid.toString();
}

class NoteHandler : public Poco::Net::HTTPRequestHandler
{
public:
    void handleRequest(Poco::Net::HTTPServerRequest &request, Poco::Net::HTTPServerResponse &response) override
    {
        Poco::URI uri(request.getURI());
        string path = uri.getPath();
        response.setChunkedTransferEncoding(false);
        response.setKeepAlive(false);

        try
        {
            if (request.getMethod() == "POST" && path == "/register")
            {
                Poco::Net::HTMLForm form(request, request.stream());
                string username = form.get("username", "");
                string password = form.get("password", "");
                string user_public_key = form.get("user_public_key", "");
                if (username.empty() || password.empty())
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
                    response.send() << "missing fields\n";
                    return;
                }
                lock_guard<mutex> g(g_mtx);
                if (g_users.count(username))
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
                    response.send() << "user exists\n";
                    return;
                }
                User u;
                u.salt_hex = generate_salt_hex(16);
                u.iterations = 100000;
                u.password_hash = pbkdf2_hash(password, u.salt_hex, u.iterations);
                u.token.clear();
                u.user_public_key = user_public_key;
                g_users[username] = u;

                response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
                response.send() << "registered\n";
                return;
            }

            if (request.getMethod() == "POST" && path == "/login")
            {
                Poco::Net::HTMLForm form(request, request.stream());
                string username = form.get("username", "");
                string password = form.get("password", "");
                if (username.empty() || password.empty())
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
                    response.send() << "missing fields\n";
                    return;
                }
                lock_guard<mutex> g(g_mtx);
                if (!g_users.count(username) || !pbkdf2_verify(password, g_users[username].salt_hex, g_users[username].password_hash, g_users[username].iterations))
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
                    response.send() << "unauthorized\n";
                    return;
                }
                string jti = generate_jti();
                string token = jwt_generate(username, jti);
                g_users[username].token = token;
                g_users[username].token_jti = jti;
                response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
                response.setContentType("application/json");
                {
                    Poco::JSON::Object obj;
                    obj.set("token", token);
                    ostringstream oss;
                    obj.stringify(oss);
                    response.send() << oss.str() << "\n";
                }
                return;
            }

            if (request.getMethod() == "POST" && path == "/notes")
            {
                string auth = request.get("Authorization", "");
                string token = "";
                if (auth.rfind("Bearer ", 0) == 0)
                    token = auth.substr(7);
                Poco::Net::HTMLForm form(request, request.stream());
                string content = form.get("content", "");
                if (token.empty() || content.empty())
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
                    response.send() << "missing token or content\n";
                    return;
                }
                string username_from_token, jti_from_token;
                if (!jwt_verify(token, username_from_token, jti_from_token))
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
                    response.send() << "unauthorized\n";
                    return;
                }
                lock_guard<mutex> g(g_mtx);
                string user = username_from_token;
                if (user.empty() || g_users[user].token_jti != jti_from_token)
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
                    response.send() << "unauthorized\n";
                    return;
                }
                string note_id = Poco::UUIDGenerator::defaultGenerator().createRandom().toString();
                g_notes[note_id] = Note{user, content};
                response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
                response.setContentType("application/json");
                {
                    Poco::JSON::Object obj;
                    obj.set("note_id", note_id);
                    ostringstream oss;
                    obj.stringify(oss);
                    response.send() << oss.str() << "\n";
                }
                return;
            }

            if (request.getMethod() == "POST" && path == "/share_notes")
            {
                string auth = request.get("Authorization", "");
                string token = "";
                if (auth.rfind("Bearer ", 0) == 0)
                    token = auth.substr(7);
                Poco::Net::HTMLForm form(request, request.stream());
                string content = form.get("content", "");
                if (token.empty() || content.empty())
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
                    response.send() << "missing token or content\n";
                    return;
                }
                string public_key = form.get("public_key", "");
                if (token.empty() || public_key.empty())
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
                    response.send() << "missing token or public_key\n";
                    return;
                }
                string iv = form.get("iv", "");
                if (token.empty() || iv.empty())
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
                    response.send() << "missing token or iv\n";
                    return;
                }
                string username_from_token, jti_from_token;
                if (!jwt_verify(token, username_from_token, jti_from_token))
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
                    response.send() << "unauthorized\n";
                    return;
                }
                lock_guard<mutex> g(g_mtx);
                string user = username_from_token;
                if (user.empty() || g_users[user].token_jti != jti_from_token)
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
                    response.send() << "unauthorized\n";
                    return;
                }
                string note_id = Poco::UUIDGenerator::defaultGenerator().createRandom().toString();
                g_shared_notes[note_id] = SharedNote{user, content, public_key, iv};
                response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
                response.setContentType("application/json");
                {
                    Poco::JSON::Object obj;
                    obj.set("note_id", note_id);
                    ostringstream oss;
                    obj.stringify(oss);
                    response.send() << oss.str() << "\n";
                }
                return;
            }

            if (request.getMethod() == "POST" && path == "/share")
            {
                string auth = request.get("Authorization", "");
                string token = "";
                if (auth.rfind("Bearer ", 0) == 0)
                    token = auth.substr(7);
                Poco::Net::HTMLForm form(request, request.stream());
                string note_id = form.get("note_id", "");
                if (token.empty() || note_id.empty())
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
                    response.send() << "missing token or note_id\n";
                    return;
                }
                string username_from_token, jti_from_token;
                if (!jwt_verify(token, username_from_token, jti_from_token))
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
                    response.send() << "unauthorized\n";
                    return;
                }
                lock_guard<mutex> g(g_mtx);
                string user = username_from_token;
                if (user.empty() || g_users[user].token_jti != jti_from_token)
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
                    response.send() << "unauthorized\n";
                    return;
                }
                if (!g_shared_notes.count(note_id) || g_shared_notes[note_id].owner != user)
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_FORBIDDEN);
                    response.send() << "not allowed\n";
                    return;
                }
                string t = Poco::UUIDGenerator::defaultGenerator().createRandom().toString();
                g_shares[t] = note_id;
                response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
                response.setContentType("application/json");
                {
                    Poco::JSON::Object obj;
                    obj.set("share_token", t);
                    ostringstream oss;
                    obj.stringify(oss);
                    response.send() << oss.str() << "\n";
                }
                return;
            }

            if (request.getMethod() == "POST" && path == "/delete_note")
            {
                string auth = request.get("Authorization", "");
                string token = "";
                if (auth.rfind("Bearer ", 0) == 0)
                    token = auth.substr(7);
                Poco::Net::HTMLForm form(request, request.stream());
                string note_id = form.get("note_id", "");
                if (token.empty() || note_id.empty())
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
                    response.send() << "missing token or note_id\n";
                    return;
                }
                string username_from_token, jti_from_token;
                if (!jwt_verify(token, username_from_token, jti_from_token))
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
                    response.send() << "unauthorized\n";
                    return;
                }
                lock_guard<mutex> g(g_mtx);
                string user = username_from_token;
                if (user.empty() || g_users[user].token_jti != jti_from_token)
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
                    response.send() << "unauthorized\n";
                    return;
                }
                if (!g_notes.count(note_id))
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_FOUND);
                    response.send() << "not found\n";
                    return;
                }
                if (g_notes[note_id].owner != user)
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_FORBIDDEN);
                    response.send() << "not allowed\n";
                    return;
                }
                g_notes.erase(note_id);
                response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
                response.send() << "deleted\n";
                return;
            }

            if (request.getMethod() == "POST" && path == "/delete_shared_note")
            {
                string auth = request.get("Authorization", "");
                string token = "";
                if (auth.rfind("Bearer ", 0) == 0)
                    token = auth.substr(7);
                Poco::Net::HTMLForm form(request, request.stream());
                string note_id = form.get("note_id", "");
                if (token.empty() || note_id.empty())
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
                    response.send() << "missing token or note_id\n";
                    return;
                }
                string username_from_token, jti_from_token;
                if (!jwt_verify(token, username_from_token, jti_from_token))
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
                    response.send() << "unauthorized\n";
                    return;
                }
                lock_guard<mutex> g(g_mtx);
                string user = username_from_token;
                if (user.empty() || g_users[user].token_jti != jti_from_token)
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
                    response.send() << "unauthorized\n";
                    return;
                }
                if (!g_shared_notes.count(note_id))
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_FOUND);
                    response.send() << "not found\n";
                    return;
                }
                if (g_shared_notes[note_id].owner != user)
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_FORBIDDEN);
                    response.send() << "not allowed\n";
                    return;
                }
                // remove any share tokens pointing to this shared note
                for (auto it = g_shares.begin(); it != g_shares.end();)
                {
                    if (it->second == note_id)
                        it = g_shares.erase(it);
                    else
                        ++it;
                }
                g_shared_notes.erase(note_id);
                response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
                response.send() << "deleted\n";
                return;
            }

            if (request.getMethod() == "GET" && path.rfind("/user_public_key/", 0) == 0)
            {
                string target_user = path.substr(strlen("/user_public_key/"));
                if (target_user.empty())
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
                    response.send() << "missing user\n";
                    return;
                }

                lock_guard<mutex> g(g_mtx);
                if (!g_users.count(target_user))
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_FOUND);
                    response.send() << "no key\n";
                    return;
                }
                Poco::JSON::Object obj;
                obj.set("user_public_key", g_users[target_user].user_public_key);
                ostringstream oss;
                obj.stringify(oss);

                response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
                response.setContentType("application/json");
                response.send() << oss.str();
                return;
            }

            if (request.getMethod() == "GET" && path.rfind("/share_notes/", 0) == 0)
            {
                string token = path.substr(strlen("/share_notes/"));
                lock_guard<mutex> g(g_mtx);
                if (!g_shares.count(token))
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_FOUND);
                    response.send() << "not found\n";
                    return;
                }
                string nid = g_shares[token];
                if (!g_shared_notes.count(nid))
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_FOUND);
                    response.send() << "shared note not found\n";
                    return;
                }
                Poco::JSON::Object obj;
                obj.set("content", g_shared_notes[nid].content);
                obj.set("public_key", g_shared_notes[nid].public_key);
                obj.set("iv", g_shared_notes[nid].iv);

                ostringstream oss;
                obj.stringify(oss);

                response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
                response.setContentType("application/json");
                response.send() << oss.str();
                return;
            }

            if (request.getMethod() == "GET" && path.rfind("/notes/", 0) == 0)
            {
                string auth = request.get("Authorization", "");
                string token = "";
                if (auth.rfind("Bearer ", 0) == 0)
                    token = auth.substr(7);
                string note_id = path.substr(strlen("/notes/"));
                if (token.empty() || note_id.empty())
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
                    response.send() << "missing token or note_id\n";
                    return;
                }
                string username_from_token, jti_from_token;
                if (!jwt_verify(token, username_from_token, jti_from_token))
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
                    response.send() << "unauthorized\n";
                    return;
                }
                lock_guard<mutex> g(g_mtx);
                string user = username_from_token;
                if (user.empty() || g_users[user].token_jti != jti_from_token)
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
                    response.send() << "unauthorized\n";
                    return;
                }
                if (!g_notes.count(note_id) || g_notes[note_id].owner != user)
                {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_FORBIDDEN);
                    response.send() << "not allowed\n";
                    return;
                }
                response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
                response.send() << g_notes[note_id].content;
                return;
            }
            response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_FOUND);
            response.send() << "not found\n";
        }
        catch (Poco::Exception &ex)
        {
            response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
            response.send() << "internal error\n";
        }
    }
};

class NoteFactory : public Poco::Net::HTTPRequestHandlerFactory
{
public:
    Poco::Net::HTTPRequestHandler *createRequestHandler(const Poco::Net::HTTPServerRequest &request) override
    {
        return new NoteHandler();
    }
};

bool client_register(const string &host, int port, const string &username, const string &password, const string &user_public_key, string &resp_out)
{
    try
    {
        Poco::Net::HTTPClientSession session(host, port);
        Poco::Net::HTTPRequest req(Poco::Net::HTTPRequest::HTTP_POST, "/register", Poco::Net::HTTPMessage::HTTP_1_1);
        Poco::Net::HTMLForm form;
        form.set("username", username);
        form.set("password", password);
        form.set("user_public_key", user_public_key);
        form.prepareSubmit(req);
        ostream &os = session.sendRequest(req);
        form.write(os);
        Poco::Net::HTTPResponse res;
        istream &is = session.receiveResponse(res);
        string body_out;
        Poco::StreamCopier::copyToString(is, body_out);
        resp_out = body_out;
        return res.getStatus() == Poco::Net::HTTPResponse::HTTP_OK;
    }
    catch (Poco::Exception &ex)
    {
        resp_out = ex.displayText();
        return false;
    }
}

bool client_login(const string &host, int port, const string &username, const string &password, string &token_out, string &resp_out)
{
    try
    {
        Poco::Net::HTTPClientSession session(host, port);
        Poco::Net::HTTPRequest req(Poco::Net::HTTPRequest::HTTP_POST, "/login", Poco::Net::HTTPMessage::HTTP_1_1);
        Poco::Net::HTMLForm form;
        form.set("username", username);
        form.set("password", password);
        form.prepareSubmit(req);
        ostream &os = session.sendRequest(req);
        form.write(os);
        Poco::Net::HTTPResponse res;
        istream &is = session.receiveResponse(res);
        string body_out;
        Poco::StreamCopier::copyToString(is, body_out);
        resp_out = body_out;
        if (res.getStatus() != Poco::Net::HTTPResponse::HTTP_OK)
            return false;
        try
        {
            Poco::JSON::Parser parser;
            Poco::Dynamic::Var var = parser.parse(body_out);
            Poco::JSON::Object::Ptr obj = var.extract<Poco::JSON::Object::Ptr>();
            if (obj->has("token"))
            {
                token_out = obj->getValue<std::string>("token");
                return true;
            }
        }
        catch (...)
        {
        }
        return false;
    }
    catch (Poco::Exception &ex)
    {
        resp_out = ex.displayText();
        return false;
    }
}

bool client_add_note(const string &host, int port, const string &token, const string &content, string &note_id_out, string &resp_out)
{
    try
    {
        Poco::Net::HTTPClientSession session(host, port);
        Poco::Net::HTTPRequest req(Poco::Net::HTTPRequest::HTTP_POST, "/notes", Poco::Net::HTTPMessage::HTTP_1_1);
        req.set("Authorization", string("Bearer ") + token);
        Poco::Net::HTMLForm form;
        form.set("content", content);
        form.prepareSubmit(req);
        ostream &os = session.sendRequest(req);
        form.write(os);
        Poco::Net::HTTPResponse res;
        istream &is = session.receiveResponse(res);
        string body_out;
        Poco::StreamCopier::copyToString(is, body_out);
        resp_out = body_out;
        if (res.getStatus() != Poco::Net::HTTPResponse::HTTP_OK)
            return false;

        Poco::JSON::Parser parser;
        Poco::Dynamic::Var var = parser.parse(body_out);
        Poco::JSON::Object::Ptr obj = var.extract<Poco::JSON::Object::Ptr>();
        if (obj->has("note_id"))
        {
            note_id_out = obj->getValue<std::string>("note_id");
            return true;
        }

        return false;
    }
    catch (Poco::Exception &ex)
    {
        resp_out = ex.displayText();
        return false;
    }
}

struct KeyPair
{
    std::vector<unsigned char> private_key;
    std::vector<unsigned char> public_key;
};

KeyPair generate_x25519_keypair()
{
    KeyPair kp;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *pkey = NULL;

    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);

    size_t priv_len = 0;
    size_t pub_len = 0;

    EVP_PKEY_get_raw_private_key(pkey, NULL, &priv_len);
    kp.private_key.resize(priv_len);
    EVP_PKEY_get_raw_private_key(pkey, kp.private_key.data(), &priv_len);

    EVP_PKEY_get_raw_public_key(pkey, NULL, &pub_len);
    kp.public_key.resize(pub_len);
    EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &pub_len);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);

    return kp;
}

bool client_get_user_public_key(const string &host, int port, const string &token, const string &target_user, string &public_key_out, string &resp_out)
{
    try
    {
        Poco::Net::HTTPClientSession session(host, port);
        Poco::URI uri;
        uri.setPath(string("/user_public_key/") + target_user);
        Poco::Net::HTTPRequest req(Poco::Net::HTTPRequest::HTTP_GET, uri.getPath(), Poco::Net::HTTPMessage::HTTP_1_1);
        req.set("Authorization", string("Bearer ") + token);
        req.set("Accept", "application/json");
        session.sendRequest(req);
        Poco::Net::HTTPResponse res;
        istream &is = session.receiveResponse(res);
        string body_out;
        Poco::StreamCopier::copyToString(is, body_out);
        resp_out = body_out;
        if (res.getStatus() != Poco::Net::HTTPResponse::HTTP_OK)
            return false;

        Poco::JSON::Parser parser;
        Poco::Dynamic::Var var = parser.parse(body_out);
        Poco::JSON::Object::Ptr obj = var.extract<Poco::JSON::Object::Ptr>();

        if (obj->has("user_public_key"))
        {
            public_key_out = obj->getValue<std::string>("user_public_key");
            return true;
        }

        return false;
    }
    catch (Poco::Exception &ex)
    {
        cerr << "Poco Exception: " << ex.displayText() << endl;
        resp_out = ex.displayText();
        return false;
    }
}

bool client_get_user_public_keys(const string &host, int port, const string &token, vector<string> &public_keys_out, string &resp_out)
{
    try
    {
        Poco::Net::HTTPClientSession session(host, port);
        Poco::Net::HTTPRequest req(Poco::Net::HTTPRequest::HTTP_GET, "/user_public_keys", Poco::Net::HTTPMessage::HTTP_1_1);
        req.set("Authorization", string("Bearer ") + token);
        req.set("Accept", "application/json");
        session.sendRequest(req);
        Poco::Net::HTTPResponse res;
        istream &is = session.receiveResponse(res);
        string body_out;
        Poco::StreamCopier::copyToString(is, body_out);
        resp_out = body_out;
        if (res.getStatus() != Poco::Net::HTTPResponse::HTTP_OK)
            return false;
        Poco::JSON::Parser parser;
        Poco::Dynamic::Var var = parser.parse(body_out);
        Poco::JSON::Object::Ptr obj = var.extract<Poco::JSON::Object::Ptr>();
        if (obj->has("public_keys"))
        {
            Poco::JSON::Array::Ptr arr = obj->getArray("public_keys");
            for (size_t i = 0; i < arr->size(); ++i)
            {
                Poco::Dynamic::Var v = arr->get(i);
                if (!v.isEmpty())
                    public_keys_out.push_back(v.toString());
            }
            return true;
        }
        return false;
    }
    catch (Poco::Exception &ex)
    {
        cerr << "Poco Exception: " << ex.displayText() << endl;
        resp_out = ex.displayText();
        return false;
    }
}

bool client_delete_note(const string &host, int port, const string &token, const string &note_id, string &resp_out)
{
    try
    {
        Poco::Net::HTTPClientSession session(host, port);
        Poco::Net::HTTPRequest req(Poco::Net::HTTPRequest::HTTP_POST, "/delete_note", Poco::Net::HTTPMessage::HTTP_1_1);
        req.set("Authorization", string("Bearer ") + token);
        Poco::Net::HTMLForm form;
        form.set("note_id", note_id);
        form.prepareSubmit(req);
        ostream &os = session.sendRequest(req);
        form.write(os);
        Poco::Net::HTTPResponse res;
        istream &is = session.receiveResponse(res);
        string body_out;
        Poco::StreamCopier::copyToString(is, body_out);
        resp_out = body_out;
        return res.getStatus() == Poco::Net::HTTPResponse::HTTP_OK;
    }
    catch (Poco::Exception &ex)
    {
        resp_out = ex.displayText();
        return false;
    }
}

bool client_delete_shared_note(const string &host, int port, const string &token, const string &note_id, string &resp_out)
{
    try
    {
        Poco::Net::HTTPClientSession session(host, port);
        Poco::Net::HTTPRequest req(Poco::Net::HTTPRequest::HTTP_POST, "/delete_shared_note", Poco::Net::HTTPMessage::HTTP_1_1);
        req.set("Authorization", string("Bearer ") + token);
        Poco::Net::HTMLForm form;
        form.set("note_id", note_id);
        form.prepareSubmit(req);
        ostream &os = session.sendRequest(req);
        form.write(os);
        Poco::Net::HTTPResponse res;
        istream &is = session.receiveResponse(res);
        string body_out;
        Poco::StreamCopier::copyToString(is, body_out);
        resp_out = body_out;
        return res.getStatus() == Poco::Net::HTTPResponse::HTTP_OK;
    }
    catch (Poco::Exception &ex)
    {
        resp_out = ex.displayText();
        return false;
    }
}

vector<unsigned char> compute_shared_key(
    const vector<unsigned char> &my_private,
    const vector<unsigned char> &their_public)
{
    EVP_PKEY *my_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                     my_private.data(), my_private.size());

    EVP_PKEY *their_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                                       their_public.data(), their_public.size());

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_pkey, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, their_pkey);

    size_t shared_len = 0;
    EVP_PKEY_derive(ctx, NULL, &shared_len);

    vector<unsigned char> shared(shared_len);
    EVP_PKEY_derive(ctx, shared.data(), &shared_len);

    EVP_PKEY_free(my_pkey);
    EVP_PKEY_free(their_pkey);
    EVP_PKEY_CTX_free(ctx);

    return shared;
}

bool client_add_shared_note(const string &host, int port, const string &token, const string &content, const string &public_key_hex, const string &iv, string &note_id_out, string &resp_out)
{
    try
    {
        Poco::Net::HTTPClientSession session(host, port);
        Poco::Net::HTTPRequest req(Poco::Net::HTTPRequest::HTTP_POST, "/share_notes", Poco::Net::HTTPMessage::HTTP_1_1);
        req.set("Authorization", string("Bearer ") + token);
        Poco::Net::HTMLForm form;

        form.set("content", content);
        form.set("public_key", public_key_hex);
        form.set("iv", iv);

        form.prepareSubmit(req);
        ostream &os = session.sendRequest(req);
        form.write(os);
        Poco::Net::HTTPResponse res;
        istream &is = session.receiveResponse(res);
        string body_out;
        Poco::StreamCopier::copyToString(is, body_out);
        resp_out = body_out;
        if (res.getStatus() != Poco::Net::HTTPResponse::HTTP_OK)
            return false;

        Poco::JSON::Parser parser;
        Poco::Dynamic::Var var = parser.parse(body_out);
        Poco::JSON::Object::Ptr obj = var.extract<Poco::JSON::Object::Ptr>();
        if (obj->has("note_id"))
        {
            note_id_out = obj->getValue<std::string>("note_id");
            return true;
        }

        return false;
    }
    catch (Poco::Exception &ex)
    {
        resp_out = ex.displayText();
        return false;
    }
}

bool client_upload_user_public_key(const string &host, int port, const string &token, const string &pub_hex, string &resp_out)
{
    try
    {
        Poco::Net::HTTPClientSession session(host, port);
        Poco::Net::HTTPRequest req(Poco::Net::HTTPRequest::HTTP_POST, "/user_public_key", Poco::Net::HTTPMessage::HTTP_1_1);
        req.set("Authorization", string("Bearer ") + token);

        Poco::Net::HTMLForm form;
        form.set("user_public_key", pub_hex);
        form.prepareSubmit(req);

        ostream &os = session.sendRequest(req);
        form.write(os);

        Poco::Net::HTTPResponse res;
        istream &is = session.receiveResponse(res);

        Poco::StreamCopier::copyToString(is, resp_out);
        return res.getStatus() == Poco::Net::HTTPResponse::HTTP_OK;
    }
    catch (Poco::Exception &ex)
    {
        resp_out = ex.displayText();
        return false;
    }
}

bool client_share_note(const string &host, int port, const string &token, const string &note_id, string &share_token_out, string &resp_out)
{
    try
    {
        Poco::Net::HTTPClientSession session(host, port);
        Poco::Net::HTTPRequest req(Poco::Net::HTTPRequest::HTTP_POST, "/share", Poco::Net::HTTPMessage::HTTP_1_1);
        req.set("Authorization", string("Bearer ") + token);
        Poco::Net::HTMLForm form;
        form.set("note_id", note_id);
        form.prepareSubmit(req);
        ostream &os = session.sendRequest(req);
        form.write(os);
        Poco::Net::HTTPResponse res;
        istream &is = session.receiveResponse(res);
        string body_out;
        Poco::StreamCopier::copyToString(is, body_out);
        resp_out = body_out;
        if (res.getStatus() != Poco::Net::HTTPResponse::HTTP_OK)
            return false;
        Poco::JSON::Parser parser;
        Poco::Dynamic::Var var = parser.parse(body_out);
        Poco::JSON::Object::Ptr obj = var.extract<Poco::JSON::Object::Ptr>();
        if (obj->has("share_token"))
        {
            share_token_out = obj->getValue<std::string>("share_token");
            return true;
        }

        return false;
    }
    catch (Poco::Exception &ex)
    {
        resp_out = ex.displayText();
        return false;
    }
}

bool client_get_shared_note(const string &host, int port, const string &share_token,
                            string &content_out, string &public_key_out, string &iv_out, string &resp_out)
{
    try
    {
        Poco::Net::HTTPClientSession session(host, port);
        Poco::URI uri;
        uri.setPath(string("/share_notes/") + share_token);
        Poco::Net::HTTPRequest req(Poco::Net::HTTPRequest::HTTP_GET, uri.getPath(), Poco::Net::HTTPMessage::HTTP_1_1);
        Poco::Net::HTTPResponse res;
        ostream &os = session.sendRequest(req);
        istream &is = session.receiveResponse(res);
        string body_out;
        Poco::StreamCopier::copyToString(is, body_out);
        resp_out = body_out;
        if (res.getStatus() != Poco::Net::HTTPResponse::HTTP_OK)
            return false;

        Poco::JSON::Parser parser;
        Poco::Dynamic::Var result = parser.parse(body_out);
        Poco::JSON::Object::Ptr obj = result.extract<Poco::JSON::Object::Ptr>();
        if (obj->has("content"))
            content_out = obj->getValue<std::string>("content");
        if (obj->has("public_key"))
            public_key_out = obj->getValue<std::string>("public_key");
        if (obj->has("iv"))
            iv_out = obj->getValue<std::string>("iv");
        return true;
    }
    catch (Poco::Exception &ex)
    {
        resp_out = ex.displayText();
        return false;
    }
}

bool client_get_note(const string &host, int port, const string &token, const string &note_id, string &content_out, string &resp_out)
{
    try
    {
        Poco::Net::HTTPClientSession session(host, port);
        Poco::URI uri;
        uri.setPath(string("/notes/") + note_id);
        Poco::Net::HTTPRequest req(Poco::Net::HTTPRequest::HTTP_GET, uri.getPath(), Poco::Net::HTTPMessage::HTTP_1_1);
        req.set("Authorization", string("Bearer ") + token);
        Poco::Net::HTTPResponse res;
        ostream &os = session.sendRequest(req);
        istream &is = session.receiveResponse(res);
        string body_out;
        Poco::StreamCopier::copyToString(is, body_out);
        resp_out = body_out;
        if (res.getStatus() != Poco::Net::HTTPResponse::HTTP_OK)
            return false;
        content_out = body_out;
        return true;
    }
    catch (Poco::Exception &ex)
    {
        resp_out = ex.displayText();
        return false;
    }
}

bool aes256_encrypt(const std::string &plaintext, const unsigned char *key, const unsigned char *iv, std::vector<unsigned char> &ciphertext)
{
    // Placeholder for AES-256 encryption function
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    int len = 0;
    int ciphertext_len = 0;

    ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char *>(plaintext.data()), static_cast<int>(plaintext.size())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aes256_decrypt(const vector<unsigned char> &ciphertext, const unsigned char *key, const unsigned char *iv, string &plaintext)
{

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    int len = 0;
    int plaintext_len = 0;

    vector<unsigned char> buffer(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);

    // Dùng AES-256-CBC
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptUpdate(ctx, buffer.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, buffer.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;

    buffer.resize(plaintext_len);
    plaintext.assign(buffer.begin(), buffer.end());

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

std::string readFile(std::string filepath)
{
    fstream input;
    input.open(filepath, ios::in);

    std::string content;
    std::string line;
    while (!input.eof())
    {
        std::getline(input, line);
        content += line + "\n";
    }
    return content;
}

int main()
{
    int role = 0;
    cout << "Choose role (0: client, 1: server)\n";
    cin >> role;
    cin.ignore();

    if (role == 1)
    {
        int port = 8080;
        cout << "Starting Poco HTTP server on port " << port << "...\n";
        try
        {
            Poco::Net::ServerSocket svs(port);
            Poco::Net::HTTPServer srv(new NoteFactory(), svs, new Poco::Net::HTTPServerParams);
            srv.start();
            cout << "Poco HTTP server running on 0.0.0.0:" << port << "\n";
            cout << "Press Enter to quit...\n";
            string ignore;
            getline(cin, ignore);
            srv.stop();
        }
        catch (Poco::Exception &ex)
        {
            cout << "Poco server error: " << ex.displayText() << "\n";
            return 1;
        }
    }
    else if (role == 0)
    {
        string host;
        int port;
        cout << "Enter server host (default 127.0.0.1): ";
        getline(cin, host);
        if (host.empty())
            host = "127.0.0.1";
        port = 8080;

        string logged_token;
        string logged_user;
        vector<unsigned char> user_private_key;
        map<string, pair<string, string>> read_content_note;

        while (true)
        {
            cout << "\nClient Menu:\n";
            cout << "  1) Register\n";
            cout << "  2) Login\n";
            cout << "  3) Add Note\n";
            cout << "  4) Share Note\n";
            cout << "  5) Get Shared Note\n";
            cout << "  6) Log out\n";
            cout << "  7) Get My Note by ID\n";
            cout << "  8) List Notes IDs\n";
            cout << "  9) Delete Note\n";
            cout << "  10) Delete Shared Note\n";
            cout << "Choose option: ";
            int opt;
            cin >> opt;
            cin.ignore();
            if (opt == 1)
            {
                cout << "Username: ";
                string username;
                getline(cin, username);
                cout << "Password: ";
                string password;
                getline(cin, password);

                KeyPair kp = generate_x25519_keypair();
                user_private_key = kp.private_key;
                string user_public_key = hex_encode(kp.public_key.data(), kp.public_key.size());

                string resp;
                bool ok = client_register(host, port, username, password, user_public_key, resp);
                cout << "Server response:\n"
                     << resp << "\n";
                if (!ok)
                {
                    cout << "Register failed\n";
                    continue;
                }
                cout << "Registered successfully\n";
            }
            else if (opt == 2)
            {
                cout << "Username: ";
                string username;
                getline(cin, username);
                cout << "Password: ";
                string password;
                getline(cin, password);
                string resp;
                string token;
                bool ok = client_login(host, port, username, password, token, resp);
                cout << "Server response:\n"
                     << resp << "\n";
                if (ok)
                {
                    logged_token = token;
                    logged_user = username;
                    cout << "Login successful\n";
                }
                else
                    cout << "Login failed\n";
            }
            else if (opt == 3)
            {
                if (logged_token.empty())
                {
                    cout << "Not logged in. Please login first.\n";
                    continue;
                }

                cout << "File path: ";
                string filepath;
                getline(cin, filepath);

                string plaintext = readFile(filepath);

                unsigned char key_hex[32];
                unsigned char iv_hex[16];
                if (RAND_bytes(key_hex, sizeof(key_hex)) != 1 || RAND_bytes(iv_hex, sizeof(iv_hex)) != 1)
                {
                    cout << "RAND_bytes failed\n";
                    continue;
                }

                vector<unsigned char> cipher_hexv;
                bool is_encrypt_successfully = aes256_encrypt(plaintext, key_hex, iv_hex, cipher_hexv);
                if (!is_encrypt_successfully)
                {
                    cout << "encrypt content failed\n";
                    continue;
                }

                string ciphertext = hex_encode(cipher_hexv.data(), cipher_hexv.size());
                string iv = hex_encode(iv_hex, sizeof(iv_hex));
                string key = hex_encode(key_hex, sizeof(key_hex));

                string resp;
                string note_id;
                bool ok = client_add_note(host, port, logged_token, ciphertext, note_id, resp);
                cout << "Server response:\n"
                     << resp << "\n";
                if (ok)
                    cout << "Created note id: " << note_id << "\n";
                else
                    cout << "Create note failed\n";

                read_content_note[note_id] = make_pair(key, iv);
            }
            else if (opt == 4)
            {
                if (logged_token.empty())
                {
                    cout << "Not logged in. Please login first.\n";
                    continue;
                }
                cout << "Note ID: ";
                string note_id;
                getline(cin, note_id);

                // get the content of shared note
                string ciphertext;
                string resp_get_note;
                bool is_get_note_successfully = client_get_note(host, port, logged_token, note_id, ciphertext, resp_get_note);
                cout << "Server response:\n"
                     << resp_get_note << "\n";
                if (!is_get_note_successfully)
                {
                    cout << "get the content of note: " << note_id << " failed\n";
                    continue;
                }

                string key = read_content_note[note_id].first;
                string iv = read_content_note[note_id].second;
                string plaintext;

                vector<unsigned char> cipher_hexv = hex_decode(ciphertext);
                vector<unsigned char> key_hexv = hex_decode(key);
                vector<unsigned char> iv_hexv = hex_decode(iv);

                bool is_decrypt_successfully = aes256_decrypt(cipher_hexv, key_hexv.data(), iv_hexv.data(), plaintext);
                if (!is_decrypt_successfully)
                {
                    cout << "decrypt the content of note: " << note_id << " failed\n";
                    continue;
                }

                // get the user_public_key of target user
                cout << "Target User: ";
                string target_user;
                getline(cin, target_user);

                string resp_get_user_pubkey;
                string target_pubkey;
                bool is_get_user_pubkey_successfully = client_get_user_public_key(host, port, logged_token, target_user, target_pubkey, resp_get_user_pubkey);
                cout << "Server response:\n"
                     << resp_get_user_pubkey << "\n";
                if (!is_get_user_pubkey_successfully)
                {
                    cout << "get the user_public_key of target user failed\n";
                    continue;
                }

                vector<unsigned char> target_pubkey_hex = hex_decode(target_pubkey);

                // generate ephemeral keypair and compute shared
                KeyPair kp = generate_x25519_keypair();
                string dh_public_key = hex_encode(kp.public_key.data(), kp.public_key.size());

                vector<unsigned char> shared = compute_shared_key(kp.private_key, target_pubkey_hex);
                if (shared.empty())
                {
                    cout << "derive shared key failed\n";
                    continue;
                }

                // encrypt the shared note before uploading
                unsigned char iv_hex[16];
                if (RAND_bytes(iv_hex, sizeof(iv_hex)) != 1)
                {
                    cout << "RAND_bytes failed\n";
                    continue;
                }

                vector<unsigned char> cipher_hex_shared_note;
                bool is_encrypt_successfully = aes256_encrypt(plaintext, shared.data(), iv_hex, cipher_hex_shared_note);
                if (!is_encrypt_successfully)
                {
                    cout << "encrypt content failed\n";
                    continue;
                }

                string ciphertext_shared_note = hex_encode(cipher_hex_shared_note.data(), cipher_hex_shared_note.size());
                string iv_shared_note = hex_encode(iv_hex, sizeof(iv_hex));

                // upload the encrypted content
                string shared_note_id;
                string resp_add_shared_node;
                bool is_share_note_successfully = client_add_shared_note(host, port, logged_token,
                                                                         ciphertext_shared_note, dh_public_key, iv_shared_note, shared_note_id, resp_add_shared_node);

                cout << "Server response:\n"
                     << resp_add_shared_node << "\n";
                if (!is_share_note_successfully)
                {
                    cout << "Upload encrypted content failed\n";
                    continue;
                }
                cout << "Upload encrypted content successfully, shared_note_id=" << shared_note_id << "\n";

                // create share token that points to this shared note
                string resp, share_token;
                bool ok = client_share_note(host, port, logged_token, shared_note_id, share_token, resp);
                cout << "Server response:\n"
                     << resp << "\n";
                if (ok)
                    cout << "Share token: " << share_token << "\n";
                else
                    cout << "Share note failed\n";
            }

            else if (opt == 5)
            {
                if (logged_token.empty())
                {
                    cout << "Not logged in. Please login first.\n";
                    continue;
                }
                cout << "Share token: ";
                string share_token;
                getline(cin, share_token);

                // get the encrypted content of shared note
                string resp;
                string ciphertext;
                string public_key;
                string iv;
                bool ok = client_get_shared_note(host, port, share_token, ciphertext, public_key, iv, resp);
                cout << "Server response:\n"
                     << resp << "\n";
                if (!ok)
                {
                    cout << "Get shared note failed\n";
                    continue;
                }

                cout << "Receive ciphertext and public_key successfully\n";

                vector<unsigned char> cipher_hex = hex_decode(ciphertext);
                vector<unsigned char> public_key_hexv = hex_decode(public_key);
                vector<unsigned char> iv_hexv = hex_decode(iv);

                // generate compute_shared_key and decrypt
                vector<unsigned char> shared_key = compute_shared_key(user_private_key, public_key_hexv);
                if (shared_key.empty())
                {
                    cout << "derive shared key failed\n";
                    continue;
                }

                string plaintext;
                bool is_decrypt_successfully = aes256_decrypt(cipher_hex, shared_key.data(), iv_hexv.data(), plaintext);
                if (!is_decrypt_successfully)
                {
                    cout << "Decrypt failed\n";
                    continue;
                }
                cout << "Shared content: " << plaintext << "\n";
            }

            else if (opt == 6)
            {
                logged_token.clear();
                logged_user.clear();
                continue;
            }
            else if (opt == 7)
            {
                if (logged_token.empty())
                {
                    cout << "Not logged in. Please login first.\n";
                    continue;
                }
                cout << "Note ID: ";
                string note_id;
                getline(cin, note_id);

                string resp;
                string ciphertext;
                bool ok = client_get_note(host, port, logged_token, note_id, ciphertext, resp);
                cout << "Server response:\n"
                     << resp << "\n";
                if (!ok)
                {
                    cout << "get note failed\n";
                    continue;
                }

                string key = read_content_note[note_id].first;
                string iv = read_content_note[note_id].second;
                string plaintext;

                vector<unsigned char> cipher_hexv = hex_decode(ciphertext);
                vector<unsigned char> key_hexv = hex_decode(key);
                vector<unsigned char> iv_hexv = hex_decode(iv);

                bool is_decrypt_successfully = aes256_decrypt(cipher_hexv, key_hexv.data(), iv_hexv.data(), plaintext);
                if (!is_decrypt_successfully)
                {
                    cout << "decrypt the content of note: " << note_id << " failed\n";
                    continue;
                }
                cout << "Note content: " << plaintext << "\n";
            }
            else if (opt == 8)
            {
                if (logged_token.empty())
                {
                    cout << "Not logged in. Please login first.\n";
                    continue;
                }
                if (read_content_note.empty())
                {
                    cout << "No local notes stored\n";
                }
                else
                {
                    cout << "Local stored note IDs:\n";
                    for (const auto &it : read_content_note)
                    {
                        cout << "  - " << it.first << "\n";
                    }
                }
            }
            else if (opt == 9)
            {
                if (logged_token.empty())
                {
                    cout << "Not logged in. Please login first.\n";
                    continue;
                }
                cout << "Note ID: ";
                string note_id;
                getline(cin, note_id);
                string resp;
                bool ok = client_delete_note(host, port, logged_token, note_id, resp);
                cout << "Server response:\n"
                     << resp << "\n";
                if (ok)
                {
                    cout << "Deleted note: " << note_id << "\n";
                    // remove local stored key/iv for the note
                    if (read_content_note.count(note_id))
                        read_content_note.erase(note_id);
                }
                else
                {
                    cout << "Delete note failed\n";
                }
            }
            else if (opt == 10)
            {
                if (logged_token.empty())
                {
                    cout << "Not logged in. Please login first.\n";
                    continue;
                }
                cout << "Shared Note ID: ";
                string shared_note_id;
                getline(cin, shared_note_id);
                string resp;
                bool ok = client_delete_shared_note(host, port, logged_token, shared_note_id, resp);
                cout << "Server response:\n"
                     << resp << "\n";
                if (ok)
                    cout << "Deleted shared note: " << shared_note_id << "\n";
                else
                    cout << "Delete shared note failed\n";
            }
            else
                cout << "Unknown option\n";
        }
    }
    else
    {
        cout << "Invalid role selected.\n";
    }
    return 0;
}
