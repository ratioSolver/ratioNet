#include <thread>
#include "server.hpp"

class test_server : public network::server
{
#ifdef ENABLE_AUTH
    std::string generate_token(const std::string &username, const std::string &password) { return ""; }

    bool has_permission(const network::request &req, const std::string &token) { return true; }
#endif
};

void test_rest_server()
{
    test_server server;

    server.add_route(network::verb::Get, "/", [](network::request &req)
                     { return std::make_unique<network::html_response>("<html><body><h1>Hello, World!</h1></body></html>"); });
    server.add_route(network::verb::Get, "/json", [](network::request &req)
                     { return std::make_unique<network::json_response>(json::json{{"message", "Hello, World!"}}); });
    server.add_route(network::verb::Get, "/ws", [](network::request &req)
                     { return std::make_unique<network::html_response>(R"(<html><body><script>
                        var ws = new WebSocket("ws://localhost:8080/ws");
                        ws.onopen = function() { document.body.innerHTML += "<p>Connected!</p>"; ws.send("Hello, World!"); };
                        ws.onmessage = function(event) { document.body.innerHTML += "<p>" + event.data + "</p>"; };
                        ws.onclose = function() { document.body.innerHTML += "<p>Disconnected!</p>"; };
                        ws.onerror = function() { document.body.innerHTML += "<p>Error!</p>"; };
                        </script></body></html>)"); });

    server.add_ws_route("/ws").on_open([](network::ws_session &s)
                                       { s.send("Hello, World!"); })
        .on_message([](network::ws_session &s, const std::string &msg)
                    { s.send(msg); });

    std::thread t{[&server]
                  { server.start(); }};
    std::this_thread::sleep_for(std::chrono::seconds(100));
    server.stop();
    t.join();
}

int main(int argc, char const *argv[])
{
    test_rest_server();

    return 0;
}
