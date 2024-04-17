#include <thread>
#include "server.hpp"

int main(int argc, char const *argv[])
{
    network::server server;
    server.start();

    std::this_thread::sleep_for(std::chrono::seconds(10));

    return 0;
}
