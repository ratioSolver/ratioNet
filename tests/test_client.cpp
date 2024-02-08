#include <iostream>
#include "client.hpp"

int main(int argc, char const *argv[])
{
    network::client client;
    auto res = client.get<boost::beast::http::string_body>("/");
    std::cout << res << std::endl;

    return 0;
}