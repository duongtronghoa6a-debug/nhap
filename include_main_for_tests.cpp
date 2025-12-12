#define main main_for_tests
#include "../main.cpp"
#undef main

static Poco::Net::ServerSocket *g_test_svs = nullptr;
static Poco::Net::HTTPServer *g_test_srv = nullptr;

extern "C" int start_test_server()
{
    if (g_test_srv)
        return g_test_svs->address().port();
    g_test_svs = new Poco::Net::ServerSocket(0);
    g_test_srv = new Poco::Net::HTTPServer(new NoteFactory(), *g_test_svs, new Poco::Net::HTTPServerParams);
    g_test_srv->start();
    return g_test_svs->address().port();
}

extern "C" void stop_test_server()
{
    if (!g_test_srv)
        return;
    g_test_srv->stop();
    delete g_test_srv;
    g_test_srv = nullptr;
    if (g_test_svs)
    {
        delete g_test_svs;
        g_test_svs = nullptr;
    }
}
