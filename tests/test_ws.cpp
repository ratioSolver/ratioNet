#include <iostream>
#include <thread>
#include "ws_client.hpp"

int main(int argc, char const *argv[])
{
    network::ws_client client;
    std::this_thread::sleep_for(std::chrono::seconds(5));
    client.send("Hello, world!");
    std::this_thread::sleep_for(std::chrono::seconds(5));
    return 0;
}