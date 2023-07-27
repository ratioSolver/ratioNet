#include "server.h"
#include "websocket_client.h"
#include "logging.h"
#include <thread>

void test_websocket()
{
    LOG("Test WebSocket");

    network::server server;
    server.add_ws_route("/ws")
        .on_open([](network::websocket_session &ws)
                 { LOG("Server: WebSocket opened"); })
        .on_message([](network::websocket_session &ws, const std::string &msg)
                    {
                        LOG("Server: Received: " << msg);
                        ws.send("World"); })
        .on_error([](network::websocket_session &ws, const boost::system::error_code &ec)
                  { LOG("Server: " << ec.message()); })
        .on_close([](network::websocket_session &ws)
                  { LOG("Server: WebSocket closed"); });

    auto srv_future = std::async(std::launch::async, [&server]()
                                 { server.start(); });

    std::this_thread::sleep_for(std::chrono::seconds(1));

    network::websocket_client client("localhost", "8080", "/ws");
    client.on_open([]()
                   { LOG("Client: WebSocket opened"); })
        .on_message([](const std::string &msg)
                    { LOG("Client: Received: " << msg); })
        .on_error([](const boost::system::error_code &ec)
                  { LOG("Client: " << ec.message()); })
        .on_close([]()
                  { LOG("Client: WebSocket closed"); });

    std::this_thread::sleep_for(std::chrono::seconds(1));
    auto cl_future = std::async(std::launch::async, [&client]()
                                { client.start(); });

    std::this_thread::sleep_for(std::chrono::seconds(1));
    client.send("Hello");

    std::this_thread::sleep_for(std::chrono::seconds(1));
    client.close();

    std::this_thread::sleep_for(std::chrono::seconds(1));
    server.stop();
}

int main()
{
    test_websocket();

    return 0;
}
