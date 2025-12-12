#include <catch2/catch_all.hpp>
#include <thread>
#include <vector>
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Net/HTTPServerParams.h>
#include <cstring>
#include <chrono>

using namespace std;

struct KeyPair
{
    std::vector<unsigned char> private_key;
    std::vector<unsigned char> public_key;
};

extern string sha256_hex(const string &in);
extern string generate_salt_hex(size_t bytes);
extern string pbkdf2_hash(const string &password, const string &salt_hex, int iterations, int dklen);
extern bool pbkdf2_verify(const string &password, const string &salt_hex, const string &hash_hex, int iterations, int dklen);
extern string base64url_encode(const string &s);
extern string base64url_decode_to_string(const string &s);
extern string base64url_encode_bytes(const unsigned char *data, size_t len);
extern string openssl_base64_encode(const unsigned char *data, size_t len);
extern string openssl_base64_decode_to_string(const string &s);
extern string hex_encode(const unsigned char *data, size_t len);
extern vector<unsigned char> hex_decode(const string &hex);
extern string hmac_sha256(const string &key, const string &data);
extern string jwt_generate(const string &sub, const string &jti, int ttl_seconds);
extern bool jwt_verify(const string &token, string &out_sub, string &out_jti);
extern string generate_jti();
extern string openssl_base64_decode_to_string(const string &s);
extern string JWT_SECRET;
extern KeyPair generate_x25519_keypair();
extern std::vector<unsigned char> compute_shared_key(const std::vector<unsigned char> &my_private, const std::vector<unsigned char> &their_public);
extern bool client_register(const string &host, int port, const string &username, const string &password, const string &user_public_key, string &resp_out);
extern bool client_login(const string &host, int port, const string &username, const string &password, string &token_out, string &resp_out);
extern bool client_get_user_public_key(const string &host, int port, const string &token, const string &target_user, string &public_key_out, string &resp_out);
extern "C" int start_test_server();
extern "C" void stop_test_server();

TEST_CASE("sha256_hex_expected_digest_length", "[sha]")
{
    string input = "abc";
    string digest = sha256_hex(input);
    REQUIRE(digest.size() == 64);
}

TEST_CASE("pbkdf2_hash_verify_roundtrip", "[pbkdf2]")
{
    string pw = "password";
    string salt = generate_salt_hex(8);
    REQUIRE(!salt.empty());
    auto hash = pbkdf2_hash(pw, salt, 10000, 16);
    REQUIRE(!hash.empty());
    REQUIRE(pbkdf2_verify(pw, salt, hash, 10000, 16));
    REQUIRE(!pbkdf2_verify(string("wrong"), salt, hash, 10000, 16));
}

TEST_CASE("base64url_roundtrip", "[b64]")
{
    string s = "abc";
    string e = base64url_encode(s);
    string d = base64url_decode_to_string(e);
    REQUIRE(d == s);
}

TEST_CASE("jwt_hmac_verify_roundtrip", "[jwt][hmac]")
{
    string sub = "alice";
    string jti = generate_jti();
    string token = jwt_generate(sub, jti, 60);
    REQUIRE(!token.empty());
    string out_sub;
    string out_jti;
    REQUIRE(jwt_verify(token, out_sub, out_jti));
    REQUIRE(out_sub == sub);
    REQUIRE(out_jti == jti);
}

TEST_CASE("jwt_generate_verify_roundtrip", "[jwt]")
{
    string sub = "alice";
    string jti = generate_jti();
    string tok = jwt_generate(sub, jti, 60);
    REQUIRE(!tok.empty());
    string s, j;
    REQUIRE(jwt_verify(tok, s, j));
    REQUIRE(s == sub);
    REQUIRE(j == jti);
}

TEST_CASE("jwt_ttl_short_expire", "[jwt]")
{
    string sub = "alice";
    string jti = generate_jti();
    string tok = jwt_generate(sub, jti, 1);
    REQUIRE(!tok.empty());
    string s, j;
    REQUIRE(jwt_verify(tok, s, j));

    this_thread::sleep_for(chrono::seconds(2));
    REQUIRE_FALSE(jwt_verify(tok, s, j));
}

TEST_CASE("generate_jti_uniqueness", "[jti]")
{
    auto a = generate_jti();
    auto b = generate_jti();
    REQUIRE(!a.empty());
    REQUIRE(!b.empty());
    REQUIRE(a != b);
}

TEST_CASE("hex_encode_decode_roundtrip", "[hex]")
{
    const unsigned char data[] = {0x01, 0x0F, 0xFF};
    string hx = hex_encode(data, 3);
    REQUIRE(!hx.empty());
    auto out = hex_decode(hx);
    REQUIRE(out.size() == 3);
    REQUIRE(out[0] == 0x01);
    REQUIRE(out[1] == 0x0F);
    REQUIRE(out[2] == 0xFF);

    auto bad = hex_decode(string("0"));
    REQUIRE(bad.empty());
}

TEST_CASE("pbkdf2_hash_invalid_salt", "[pbkdf2]")
{
    string pw = "password";
    string bad_salt = "0";
    auto h = pbkdf2_hash(pw, bad_salt, 10000, 16);
    REQUIRE(h.empty());
    REQUIRE_FALSE(pbkdf2_verify(pw, bad_salt, string("whatever"), 10000, 16));
}

TEST_CASE("hmac_sha256_mismatch_different_key_or_data", "[hmac]")
{
    string k1 = "key1";
    string k2 = "key2";
    string d1 = "data";
    string a = hmac_sha256(k1, d1);
    string b = hmac_sha256(k2, d1);
    string c = hmac_sha256(k1, string("other"));
    REQUIRE(a != b);
    REQUIRE(a != c);
}

TEST_CASE("openssl_base64_roundtrip", "[b64]")
{
    string s = "abcd";
    string enc = openssl_base64_encode((const unsigned char *)s.data(), s.size());
    REQUIRE(!enc.empty());
    string enc_no_pad = enc;
    while (!enc_no_pad.empty() && enc_no_pad.back() == '=')
        enc_no_pad.pop_back();
    string dec = openssl_base64_decode_to_string(enc_no_pad);
    REQUIRE(dec == s);
}

TEST_CASE("base64url_encode_bytes_roundtrip", "[b64]")
{
    string orig = "abc";
    string enc = base64url_encode_bytes((const unsigned char *)orig.data(), orig.size());
    REQUIRE(!enc.empty());
    string dec = base64url_decode_to_string(enc);
    REQUIRE(dec == orig);
}

TEST_CASE("pbkdf2_different_salt_mismatch", "[pbkdf2]")
{
    string pw = "password";
    string salt1 = generate_salt_hex(8);
    string salt2 = generate_salt_hex(8);
    REQUIRE(!salt1.empty());
    REQUIRE(!salt2.empty());
    REQUIRE(salt1 != salt2);
    auto h1 = pbkdf2_hash(pw, salt1, 10000, 16);
    auto h2 = pbkdf2_hash(pw, salt2, 10000, 16);
    REQUIRE(!h1.empty());
    REQUIRE(!h2.empty());
    REQUIRE(h1 != h2);
    REQUIRE_FALSE(pbkdf2_verify(pw, salt2, h1, 10000, 16));
}

TEST_CASE("hex_decode_non_hex", "[hex]")
{
    auto out = hex_decode(string("zz"));
    REQUIRE(out.empty());
}

TEST_CASE("base64url_encode_empty", "[b64]")
{
    string enc = base64url_encode_bytes(nullptr, 0);
    REQUIRE(enc.empty());
    string dec = base64url_decode_to_string(enc);
    REQUIRE(dec.empty());
}

TEST_CASE("sha256_different_inputs", "[sha]")
{
    string a = sha256_hex(string("a"));
    string b = sha256_hex(string("b"));
    REQUIRE(a != b);
}

TEST_CASE("jwt_verify_fails_when_secret_changed", "[jwt]")
{
    string saved = JWT_SECRET;
    JWT_SECRET = string("secret-A");
    string sub = "alice";
    string jti = generate_jti();
    string token = jwt_generate(sub, jti, 60);
    REQUIRE(!token.empty());
    string out_sub, out_jti;
    REQUIRE(jwt_verify(token, out_sub, out_jti));
    JWT_SECRET = string("secret-B");
    REQUIRE_FALSE(jwt_verify(token, out_sub, out_jti));
    JWT_SECRET = saved;
}

TEST_CASE("generate_x25519_keypair_size_check", "[x25519][keypair]")
{
    const size_t X25519_KEY_SIZE = 32;

    auto kp = generate_x25519_keypair();

    REQUIRE_FALSE(kp.private_key.empty());
    REQUIRE(kp.private_key.size() == X25519_KEY_SIZE);

    REQUIRE_FALSE(kp.public_key.empty());
    REQUIRE(kp.public_key.size() == X25519_KEY_SIZE);

    REQUIRE(kp.private_key != kp.public_key);
}

TEST_CASE("compute_shared_key_roundtrip_property", "[x25519][dh]")
{
    const size_t X25519_KEY_SIZE = 32;

    auto kpAlice = generate_x25519_keypair();
    auto kpBob = generate_x25519_keypair();

    auto shared_secret_Alice = compute_shared_key(kpAlice.private_key, kpBob.public_key);
    auto shared_secret_Bob = compute_shared_key(kpBob.private_key, kpAlice.public_key);

    REQUIRE_FALSE(shared_secret_Alice.empty());
    REQUIRE(shared_secret_Alice.size() == X25519_KEY_SIZE);
    REQUIRE(shared_secret_Alice == shared_secret_Bob);
}

TEST_CASE("compute_shared_key_error_handling", "[x25519][dh][negative]")
{
    auto kp = generate_x25519_keypair();
    std::vector<unsigned char> empty_key;
    std::vector<unsigned char> bad_size_key = {0x01, 0x02};

    auto shared_A = compute_shared_key(empty_key, kp.public_key);
    REQUIRE(shared_A.empty());
    auto shared_B = compute_shared_key(kp.private_key, empty_key);
    REQUIRE(shared_B.empty());

    auto shared_C = compute_shared_key(bad_size_key, kp.public_key);
    REQUIRE(shared_C.empty());

    auto shared_D = compute_shared_key(kp.private_key, bad_size_key);
    REQUIRE(shared_D.empty());
}

TEST_CASE("server_register_login_and_errors", "[server][http]")
{
    int port = start_test_server();
    string host = "127.0.0.1";
    string username = string("t_") + generate_jti();
    string password = "password";
    KeyPair kp = generate_x25519_keypair();
    string user_pub = hex_encode(kp.public_key.data(), kp.public_key.size());

    string resp;
    bool ok = client_register(host, port, username, password, user_pub, resp);
    REQUIRE(ok);
    REQUIRE(resp.find("registered") != string::npos);

    bool ok2 = client_register(host, port, username, password, user_pub, resp);
    REQUIRE_FALSE(ok2);

    string token;
    bool login_ok = client_login(host, port, username, password, token, resp);
    REQUIRE(login_ok);
    REQUIRE(!token.empty());

    string fetched_pub;
    bool got = client_get_user_public_key(host, port, token, username, fetched_pub, resp);
    REQUIRE(got);
    REQUIRE(fetched_pub == user_pub);

    string tok2;
    bool login_fail = client_login(host, port, username, string("wrongpass"), tok2, resp);
    REQUIRE_FALSE(login_fail);

    stop_test_server();
}