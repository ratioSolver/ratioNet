#include "server.h"

int main()
{
    network::server server;
    server.add_route(boost::beast::http::verb::get, "/", [](boost::beast::http::request<boost::beast::http::string_body> &request, boost::beast::http::response<boost::beast::http::string_body> &response)
                     {
        response.result(boost::beast::http::status::ok);
        response.body() = "Hello, world!"; });

    server.run();

    return 0;
}
