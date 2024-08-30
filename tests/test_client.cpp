#include "server.hpp"
#include "client.hpp"
#include <iostream>

void test_weather_client()
{
    network::client client("api.open-meteo.com", 443);
    auto response = client.get("/v1/forecast?latitude=52.52&longitude=13.41");
    if (response)
    {
        std::cout << *response << std::endl;
    }
}

int main(int argc, char const *argv[])
{
    test_weather_client();
    return 0;
}