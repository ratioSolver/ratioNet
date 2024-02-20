#include <boost/beast/http.hpp>
#include <iostream>
#include "server.hpp"

using string_req = boost::beast::http::request<boost::beast::http::string_body>;
using string_res = boost::beast::http::response<boost::beast::http::string_body>;

void test_plain_server()
{
    network::server server("0.0.0.0", 8085);
    GET(server, "/", [](const string_req &, string_res &res)
        {
            res.set(boost::beast::http::field::content_type, "html");
            res.body() = R"(<html><body><h1>Hello, world!</h1></body></html>)"; });

    std::thread t{[&server]
                  { server.start(); }};

    std::this_thread::sleep_for(std::chrono::seconds(100));
    server.stop();
    t.join();
}

void test_ws_server()
{
    network::server server;
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

    std::this_thread::sleep_for(std::chrono::seconds(10));
    server.stop();
    t.join();
}

int main(int argc, char const *argv[])
{
    test_plain_server();
    test_ws_server();

    return 0;
}
