#include "server.hpp"
#include "client.hpp"
#include "async_client.hpp"
#include "logging.hpp"
#include <thread>

#ifdef ENABLE_SSL
void test_weather_client()
{
    network::ssl_client client("api.open-meteo.com", 443);
    auto response = client.get("/v1/forecast?latitude=52.52&longitude=13.41");
    if (response)
        LOG_INFO(*response);
}

void test_async_weather_client()
{
    network::ssl_async_client client;
    auto session = client.get_session("api.open-meteo.com", 443);
    session->get("/v1/forecast?latitude=52.52&longitude=13.41", [](const network::response &res)
                 { LOG_INFO(res); });
    session->get("/v1/forecast?latitude=48.85&longitude=2.35", [](const network::response &res)
                 { LOG_INFO(res); });
    std::this_thread::sleep_for(std::chrono::seconds(5));
}
#endif

void test_ws_client()
{
    network::server server;

    server.add_ws_route("/ws").on_open([](network::ws_server_session_base &s)
                                       { s.send("Hello, World!"); })
        .on_message([](network::ws_server_session_base &s, const network::message &msg)
                    { LOG_DEBUG("Received message: " + msg.get_payload());
                      s.send(msg.get_payload()); })
        .on_close([](network::ws_server_session_base &)
                  { LOG_INFO("Connection closed"); });

    std::thread st{[&server]
                   { server.start(); }};
    std::this_thread::sleep_for(std::chrono::seconds(2));

    network::async_client client;
    auto session = client.get_ws_session(SERVER_HOST, SERVER_PORT, "/ws");

    session->set_on_open([&session]
                         { LOG_INFO("Connected to server"); session->send("Hello, World!"); });
    session->set_on_message([](network::message &msg)
                            { LOG_INFO("Received message: " + msg.get_payload()); });
    session->set_on_close([]()
                          { LOG_INFO("Connection closed"); });
    session->set_on_error([](const std::error_code &ec)
                          { LOG_ERR(ec.message()); });

    std::this_thread::sleep_for(std::chrono::seconds(5));
    server.stop();
    st.join();
}

int main()
{
#ifdef ENABLE_SSL
    test_weather_client();
    test_async_weather_client();
#endif
    test_ws_client();
    return 0;
}