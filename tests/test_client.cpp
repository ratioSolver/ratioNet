#include "server.hpp"
#include "client.hpp"
#include "ws_client.hpp"
#include "logging.hpp"
#include <thread>

#ifdef ENABLE_SSL
void test_weather_client()
{
    network::client client("api.open-meteo.com", 443);
    auto response = client.get("/v1/forecast?latitude=52.52&longitude=13.41");
    if (response)
        LOG_INFO(*response);
}
#endif

void test_ws_client()
{
    network::server server;

#ifdef ENABLE_SSL
    server.load_certificate("cert.pem", "key.pem");
#endif

    server.add_ws_route("/ws").on_open([](network::ws_session &s)
                                       { s.send("Hello, World!"); })
        .on_message([](network::ws_session &s, std::string_view msg)
                    { LOG_DEBUG("Received message: " + std::string(msg));
                      s.send(msg); })
        .on_close([](network::ws_session &)
                  { LOG_INFO("Connection closed"); });

    std::thread st{[&server]
                   { server.start(); }};
    std::this_thread::sleep_for(std::chrono::seconds(2));

    network::ws_client client("localhost", 8080, "/ws");
    client.set_on_open([&client]
                       { LOG_INFO("Connected to server");
                         client.send("Hello, World!"); });
    client.set_on_message([](std::string_view msg)
                          { LOG_INFO("Received message: " + std::string(msg)); });
    client.set_on_close([]()
                        { LOG_INFO("Connection closed"); });
    client.set_on_error([](const std::error_code &ec)
                        { LOG_ERR(ec.message()); });
    std::thread ct{[&client]
                   { client.connect(); }};

    std::this_thread::sleep_for(std::chrono::seconds(5));
    client.disconnect();
    server.stop();
    st.join();
    ct.join();
}

int main()
{
#ifdef ENABLE_SSL
    test_weather_client();
#endif
    test_ws_client();
    return 0;
}