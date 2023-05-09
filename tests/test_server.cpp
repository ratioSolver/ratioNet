#include "server.h"

int main()
{
    network::server server;
    server.add_route(boost::beast::http::verb::get, "/", [](boost::beast::http::request<boost::beast::http::string_body> &request, boost::beast::http::response<boost::beast::http::string_body> &response)
                     {
        response.result(boost::beast::http::status::ok);
        response.set(boost::beast::http::field::content_type, "text/html");
        response.body() = R"(
            <html lang="en">
                <head>
                    <title>Test</title>
                </head>
                <body>
                    <h1>Test</h1>
                </body>
                <script type="text/javascript">
                    console.log("Hello, world!");
                    let ws = new WebSocket("ws://" + window.location.hostname + ":8080");
                    ws.onmessage = function (event) {
                        console.log(event.data);
                    };
                </script>
            </html>
        )"; });
    server.add_websocket_route("/", [](boost::beast::http::request<boost::beast::http::string_body> &request, boost::beast::websocket::stream<boost::beast::tcp_stream> &ws)
                               {
        ws.text(true);
        ws.write(boost::asio::buffer("Hello, world!")); });

    server.run();

    return 0;
}
