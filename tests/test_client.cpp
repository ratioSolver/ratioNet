#include "client.hpp"
#include <thread>
#include <iostream>

using string_res = boost::beast::http::response<boost::beast::http::string_body>;

std::function<void(const string_res &, boost::beast::error_code)> handler = [](const string_res &res, boost::beast::error_code ec)
{
    if (ec)
    {
        std::cout << "Error: " << ec.message() << std::endl;
        return;
    }
    std::cout << res.body() << std::endl;
};

void test_plain_client()
{
    network::plain_client client("www.boredapi.com", "80", [&client]()
                                 { std::cout << "Connected!" << std::endl;
                                   client.get("/api/activity", handler); });
    std::this_thread::sleep_for(std::chrono::seconds(5));
    client.get("/api/activity", handler);
    std::this_thread::sleep_for(std::chrono::seconds(5));
}

void test_ssl_client()
{
    network::ssl_client client("www.boredapi.com", "443", [&client]()
                               { std::cout << "Connected!" << std::endl;
                                   client.get("/api/activity", handler); });
    std::this_thread::sleep_for(std::chrono::seconds(5));
    client.get("/api/activity", handler);
    std::this_thread::sleep_for(std::chrono::seconds(5));
}

int main()
{
    test_plain_client();
    test_ssl_client();

    return 0;
}
