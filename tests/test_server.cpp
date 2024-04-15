#include "server.hpp"

int main(int argc, char const *argv[])
{
    network::server server;
    server.start();

    return 0;
}
