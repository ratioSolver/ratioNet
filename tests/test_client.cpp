#include "server.hpp"
#include "client.hpp"
#include <iostream>

#ifdef ENABLE_SSL
void test_weather_client()
{
    network::client client("api.open-meteo.com", 443);
    auto response = client.get("/v1/forecast?latitude=52.52&longitude=13.41");
    if (response)
        std::cout << *response << std::endl;
}
#endif

int main(int argc, char const *argv[])
{
#ifdef ENABLE_SSL
    test_weather_client();
#endif
    return 0;
}