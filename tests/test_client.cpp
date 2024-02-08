#include <iostream>
#include "async_server.hpp"
#include "client.hpp"

using string_req = boost::beast::http::request<boost::beast::http::string_body>;
using string_res = boost::beast::http::response<boost::beast::http::string_body>;

int main(int argc, char const *argv[])
{
    // we create a server to test the client
    network::async::server server;
    server.set_log_handler([](const std::string &msg)
                           { std::cout << msg << std::endl; });
    server.set_error_handler([](const std::string &msg)
                             { std::cerr << msg << std::endl; });
    GET(server, "/", [](const string_req &, string_res &res)
        {
            res.set(boost::beast::http::field::content_type, "html");
            res.body() = R"(<html><body><h1>Hello, world!</h1></body></html>)"; });

    std::thread t{[&server]
                  { server.start(); }};
    std::this_thread::sleep_for(std::chrono::seconds(5));

    // we create a client
    network::client client{"localhost"};
    auto res = client.get<boost::beast::http::string_body>("/");
    std::cout << res << std::endl;

    server.stop();
    t.join();
    return 0;
}