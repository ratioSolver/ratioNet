#include <thread>
#include "server.hpp"

int main(int argc, char const *argv[])
{
    network::server server;

    server.add_route(network::verb::GET, "/", [](network::request &req)
                     { return std::make_unique<network::html_response>("<html><body><h1>Hello, World!</h1></body></html>"); });
    server.add_route(network::verb::GET, "/json", [](network::request &req)
                     { return std::make_unique<network::json_response>(json::json{{"message", "Hello, World!"}}); });
    server.add_route(network::verb::GET, "/ws", [](network::request &req)
                     { return std::make_unique<network::html_response>("<html><body><h1>WebSocket</h1></body><script>let ws = new WebSocket('ws://localhost:8080/ws');ws.onmessage = function(event) {let p = document.createElement('p');p.textContent = event.data;document.body.appendChild(p);};</script></html>"); });

    server.add_ws_route("/ws").on_open([](network::ws_session &s)
                                       { s.send("Hello, World!"); })
        .on_message([](network::ws_session &s, const std::string &msg)
                    { s.send(msg); });

    std::thread t{[&server]
                  { server.start(); }};
    std::this_thread::sleep_for(std::chrono::seconds(100));
    server.stop();
    t.join();

    return 0;
}
