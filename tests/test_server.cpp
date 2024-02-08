#include <boost/beast/http.hpp>
#include <iostream>
#include "async_server.hpp"

using string_req = boost::beast::http::request<boost::beast::http::string_body>;
using string_res = boost::beast::http::response<boost::beast::http::string_body>;

#define GET(server, target, handler) server.add_route(boost::beast::http::verb::get, target, std::function{handler})

void test_plain_async_server()
{
    network::async::server server;
    server.set_log_handler([](const std::string &msg)
                           { std::cout << msg << std::endl; });
    server.set_error_handler([](const std::string &msg)
                             { std::cerr << msg << std::endl; });
    GET(server, "/", [](const string_req &, string_res &res)
        {
            res.set(boost::beast::http::field::content_type, "html");
            res.body() = R"(<html><body><h1>Hello, world!</h1></body></html>)"; });

    server.ws("/ws")
        .on_open([](network::websocket_session &)
                 { std::cout << "New connection" << std::endl; })
        .on_message([](network::websocket_session &, const std::string &msg)
                    { std::cout << "Received message: " << msg << std::endl; })
        .on_close([](network::websocket_session &, const boost::beast::websocket::close_reason)
                  { std::cout << "Connection closed" << std::endl; });

    std::thread t{[&server]
                  { server.start(); }};

    std::this_thread::sleep_for(std::chrono::seconds(100));
    server.stop();
    t.join();
}

int main(int argc, char const *argv[])
{
    test_plain_async_server();

    return 0;
}
