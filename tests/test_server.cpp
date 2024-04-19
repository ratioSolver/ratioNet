#include <thread>
#include "server.hpp"

int main(int argc, char const *argv[])
{
    network::server server;

    server.add_route(network::verb::GET, "/", [](network::request &req)
                     { return std::make_unique<network::html_response>("<html><body><h1>Hello, World!</h1></body></html>"); });
    server.add_route(network::verb::GET, "/json", [](network::request &req)
                     { return std::make_unique<network::json_response>(json::json{{"message", "Hello, World!"}}); });

    std::thread t{[&server]
                  { server.start(); }};
    std::this_thread::sleep_for(std::chrono::seconds(100));
    server.stop();
    t.join();

    return 0;
}
