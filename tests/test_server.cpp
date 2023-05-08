#include "server.h"

int main()
{
    network::server server;
    server.add_route(network::GET, std::regex("/"), [](network::request &req) -> network::response_ptr
                     { return new network::json_response(json::json({{"message", "Hello, world!"}})); });
    server.start();
    return 0;
}
