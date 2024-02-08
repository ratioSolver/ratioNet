#include <iostream>
#include <thread>
#include "ws_client.hpp"

int main(int argc, char const *argv[])
{
    network::ws_client client(
        "localhost", SERVER_PORT, "/ws", []()
        { std::cout << "Connected" << std::endl; },
        [](const std::string &message)
        { std::cout << "Received message: " << message << std::endl; },
        [](boost::beast::error_code ec)
        { std::cerr << ec.message() << std::endl; },
        []()
        { std::cout << "Connection closed" << std::endl; });
    std::this_thread::sleep_for(std::chrono::seconds(5));
    client.send("Hello, world!");
    std::this_thread::sleep_for(std::chrono::seconds(5));
    return 0;
}