#include "server.h"
#include "logging.h"
#include <thread>

int main()
{
    network::server server;
    server.add_route(boost::beast::http::verb::get, "/", [](network::request &req, network::response &res)
                     {
        res.set(boost::beast::http::field::content_type, "text/html");
        res.body() = R"(
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <title>Test</title>
                <link rel="icon" type="image/icon" href="public/favicon.ico">
            </head>
            <body>
                <h1>Test</h1>
                <p>Test</p>
                <script>
                    var ws = new WebSocket("ws://" + window.location.host + "/ws");
                    ws.onopen = function() {
                        console.log("Connected");
                        ws.send("Hello");
                    };
                    ws.onmessage = function(e) {
                        console.log("Received: " + e.data);
                        ws.close();
                    };
                    ws.onclose = function() {
                        console.log("Disconnected");
                    };
                </script>
            </body>
        </html>
        )"; });
    server.add_ws_route("/ws")
        .on_open([](network::websocket_session &ws)
                 {
        LOG("WebSocket opened");
        ws.send("Hello"); })
        .on_message([](network::websocket_session &ws, const std::string &msg)
                    {
        LOG("Received: " << msg);
        ws.send("World"); })
        .on_close([](network::websocket_session &ws)
                  { LOG("WebSocket closed"); });

    auto srv_future = std::async(std::launch::async, [&server]()
                                 { server.start(); });

    std::this_thread::sleep_for(std::chrono::seconds(10));

    server.stop();

    return 0;
}
