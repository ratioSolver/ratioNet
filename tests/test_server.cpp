#include <thread>
#include "server.hpp"

int main(int argc, char const *argv[])
{
    network::server server;

    std::thread t{[&server]
                  { server.start(); }};
    std::this_thread::sleep_for(std::chrono::seconds(10));
    server.stop();
    t.join();

    return 0;
}
