#include <boost/beast/http.hpp>
#include <iostream>
#include "async_server.hpp"

using string_req = boost::beast::http::request<boost::beast::http::string_body>;
using string_res = boost::beast::http::response<boost::beast::http::string_body>;

void test_plain_async_server()
{
    network::async::server server;
    server.set_log_handler([](const std::string &msg)
                           { std::cout << msg << std::endl; });
    server.set_error_handler([](const std::string &msg)
                             { std::cerr << msg << std::endl; });
    server.add_route(boost::beast::http::verb::get, "/", std::function{[](const string_req &, string_res &res)
                                                                       {
                                                                           res.set(boost::beast::http::field::content_type, "html");
                                                                           res.body() = R"(<html><body><h1>Hello, world!</h1></body></html>)";
                                                                       }});

    std::thread t{[&server]
                  { server.start(); }};

    std::this_thread::sleep_for(std::chrono::seconds(10));
    server.stop();
    t.join();
}

int main(int argc, char const *argv[])
{
    test_plain_async_server();

    return 0;
}
