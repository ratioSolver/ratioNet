#include "client.h"
#include <thread>

int main()
{
    network::ssl_client client("localhost", "8080", []()
                               { std::cout << "Connected!" << std::endl; });
    std::this_thread::sleep_for(std::chrono::seconds(1000));
    return 0;
}
