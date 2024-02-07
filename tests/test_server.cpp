#include <boost/beast/http.hpp>
#include "async_server.hpp"

using string_req = boost::beast::http::request<boost::beast::http::string_body>;
using string_res = boost::beast::http::response<boost::beast::http::string_body>;

void test_plain_async_server()
{
    network::async::server s;

    s.get("/", std::function{[](const string_req &req, string_res &res)
                             {
                                res.set(boost::beast::http::field::content_type, "html");
                                res.body() = R"(<html><body><h1>Hello, world!</h1></body></html>)"; }});

    std::thread t{[&s]
                  { s.start(); }};

    std::this_thread::sleep_for(std::chrono::seconds(10));
    s.stop();
    t.join();
}

int main(int argc, char const *argv[])
{
    test_plain_async_server();

    return 0;
}
