#include "client.h"

int main()
{
    network::client client;
    auto res = client.call(network::request(network::method::GET, "/"));
    return 0;
}
