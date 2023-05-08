#include "server.h"

int main()
{
    network::server server;
    server.add_route(network::GET, std::regex("/"), [](network::request &req) -> network::response_ptr
                     { 
                        std::string page = R"(
                        <!DOCTYPE html>
                        <html lang="en">
                        <head>
                            <title>Test</title>
                        </head>
                        <body>
                            <h1>Test</h1>
                            <p>This is a test.</p>
                        </body>

                        <script type="text/javascript">
                            var ws = new WebSocket("ws://localhost:8080");
                            ws.onopen = function() {
                                ws.send("Hello, world!");
                            };
                            ws.onmessage = function (evt) {
                                var received_msg = evt.data;
                                alert("Message is received...");
                            };
                            ws.onclose = function() {
                                alert("Connection is closed...");
                            };
                        </script>

                        </html>
                        )";
                        return new network::html_response(page); });
    server.start();
    return 0;
}
