#include <iostream>
#include <thread>
#include "async_server.hpp"
#include "ws_client.hpp"

using string_req = boost::beast::http::request<boost::beast::http::string_body>;
using string_res = boost::beast::http::response<boost::beast::http::string_body>;

int main(int argc, char const *argv[])
{
    // we create a server to test the client
    network::async::server server;
    server.set_log_handler([](const std::string &msg)
                           { std::cout << msg << std::endl; });
    server.set_error_handler([](const std::string &msg)
                             { std::cerr << msg << std::endl; });
    GET(server, "/", [](const string_req &, string_res &res)
        {
            res.set(boost::beast::http::field::content_type, "html");
            res.body() = R"(
                <html>
                    <body>
                        <h1>Hello, world!</h1>
                        <script>
                            var ws = new WebSocket("ws://" + window.location.host + "/ws");
                            ws.onopen = function() { ws.send("Hello, server!"); };
                            ws.onmessage = function(event) { alert("Message from server: " + event.data); };
                        </script>
                    </body>
                </html>)"; });

    server.ws("/ws")
        .on_open([](network::websocket_session &session)
                 { std::cout << "New connection" << std::endl; })
        .on_message([](network::websocket_session &, const std::string &msg)
                    { std::cout << "Received message: " << msg << std::endl; })
        .on_close([](network::websocket_session &, const boost::beast::websocket::close_reason)
                  { std::cout << "Connection closed" << std::endl; });

    std::thread t{[&server]
                  { server.start(); }};
    std::this_thread::sleep_for(std::chrono::seconds(5));

    // we create a client
    auto client = std::make_shared<network::ws_client>(
        "localhost", SERVER_PORT, "/ws", []()
        { std::cout << "Connected" << std::endl; },
        [](const std::string &message)
        { std::cout << "Received message: " << message << std::endl; },
        [](boost::beast::error_code ec)
        { std::cerr << ec.message() << std::endl; },
        []()
        { std::cout << "Connection closed" << std::endl; });

    client->connect();
    std::this_thread::sleep_for(std::chrono::seconds(5));
    client->send("Hello, world!");
    std::this_thread::sleep_for(std::chrono::seconds(5));

    client->disconnect();
    server.stop();
    t.join();
    return 0;
}