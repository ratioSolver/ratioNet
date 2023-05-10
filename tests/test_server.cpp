#include "server.h"
#include <set>

int main()
{
    network::server server;
    std::set<network::websocket> clients;

    server.start();

    return 0;
}
