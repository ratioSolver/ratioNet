#include "ws_client.hpp"
#include <thread>
#include <iostream>

void test_ws()
{
    network::plain_ws_client client(
        "echo.websocket.org", "80", "/",
        [&client]()
        { std::cout << "Connected!" << std::endl;
          client.send("Hello, world!"); },
        [](const std::string &msg)
        { std::cout << "Message from server: " << msg << std::endl; });
    std::this_thread::sleep_for(std::chrono::seconds(5));
    client.send("Hello, world!");
    std::this_thread::sleep_for(std::chrono::seconds(5));
}

void test_wss()
{
    network::ssl_ws_client client(
        "echo.websocket.org", "443", "/",
        [&client]()
        { std::cout << "Connected!" << std::endl;
          client.send("Hello, world!"); },
        [](const std::string &msg)
        { std::cout << "Message from server: " << msg << std::endl; });
    std::this_thread::sleep_for(std::chrono::seconds(5));
    client.send("Hello, world!");
    std::this_thread::sleep_for(std::chrono::seconds(5));
}

int main()
{
    test_ws();
    test_wss();

    return 0;
}