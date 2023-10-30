#include "ws_client.h"
#include <thread>
#include <iostream>

void test_ws()
{
    network::plain_ws_client client;
    std::this_thread::sleep_for(std::chrono::seconds(5));
    client.send("Hello, world!");
    std::this_thread::sleep_for(std::chrono::seconds(5));
}

void test_wss()
{
    network::ssl_ws_client client;
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