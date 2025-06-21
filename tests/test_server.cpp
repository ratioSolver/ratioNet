#include "server.hpp"
#ifdef ENABLE_CORS
#include "cors.hpp"
#endif
#include <thread>

/**
 * @brief Test function to set up and run a REST server with various routes.
 *
 * This function initializes a network server and sets up several routes:
 * - A root route ("/") that returns an HTML response with "Hello, World!".
 * - A JSON route ("/json") that returns a JSON response with a message "Hello, World!".
 * - A file route ("/file") that serves a file named "test.zip".
 * - A WebSocket route ("/ws") that returns an HTML page with a WebSocket client script.
 *
 * The WebSocket route ("/ws") also sets up handlers for WebSocket events:
 * - on_open: Sends "Hello, World!" when a WebSocket connection is opened.
 * - on_message: Echoes back any received message.
 *
 * The server runs in a separate thread for 5 seconds before stopping.
 */
void test_rest_server()
{
    network::server server;

    server.add_route(network::verb::Get, "/", [](network::request &)
                     { return std::make_unique<network::html_response>("<html><body><h1>Hello, World!</h1></body></html>"); });
    server.add_route(network::verb::Get, "/json", [](network::request &)
                     { return std::make_unique<network::json_response>(json::json{{"message", "Hello, World!"}}); });
    server.add_route(network::verb::Get, "/ws", [](network::request &)
                     { return std::make_unique<network::html_response>(R"(<html><body><script>
                        var ws = new WebSocket("ws://localhost:8080/ws");
                        ws.onopen = function() { document.body.innerHTML += "<p>Connected!</p>"; ws.send("Hello, World!"); };
                        ws.onmessage = function(event) { document.body.innerHTML += "<p>" + event.data + "</p>"; };
                        ws.onclose = function() { document.body.innerHTML += "<p>Disconnected!</p>"; };
                        ws.onerror = function() { document.body.innerHTML += "<p>Error!</p>"; };
                        </script></body></html>)"); });
    server.add_route(network::verb::Get, "/file", [](network::request &)
                     { return std::make_unique<network::file_response>("test.zip"); });

    server.add_ws_route("/ws").on_open([](network::ws_server_session_base &s)
                                       { s.send("Hello, World!"); })
        .on_message([](network::ws_server_session_base &s, const network::message &msg)
                    { s.send(msg.get_payload()); });

    std::thread t{[&server]
                  { server.start(); }};
    std::this_thread::sleep_for(std::chrono::seconds(20));
    server.stop();
    t.join();
}

#ifdef ENABLE_SSL
/**
 * @brief Test function to set up and run an SSL server with various routes.
 *
 * This function initializes a network SSL server and sets up several routes:
 * - A root route ("/") that returns an HTML response with "Hello, World!".
 * - A JSON route ("/json") that returns a JSON response with a message "Hello, World!".
 * - A WebSocket route ("/ws") that returns an HTML page with a WebSocket client script.
 *
 * The WebSocket route ("/ws") also sets up handlers for WebSocket events:
 * - on_open: Sends "Hello, World!" when a WebSocket connection is opened.
 * - on_message: Echoes back any received message.
 *
 * The server runs in a separate thread for 5 seconds before stopping.
 */
void test_ssl_server()
{
    network::ssl_server server;

    server.load_certificate("cert.pem", "key.pem");

    server.add_route(network::verb::Get, "/", [](network::request &)
                     { return std::make_unique<network::html_response>("<html><body><h1>Hello, World!</h1></body></html>"); });
    server.add_route(network::verb::Get, "/json", [](network::request &)
                     { return std::make_unique<network::json_response>(json::json{{"message", "Hello, World!"}}); });
    server.add_route(network::verb::Get, "/ws", [](network::request &)
                     { return std::make_unique<network::html_response>(R"(<html><body><script>
                        var ws = new WebSocket("ws://localhost:8080/ws");
                        ws.onopen = function() { document.body.innerHTML += "<p>Connected!</p>"; ws.send("Hello, World!"); };
                        ws.onmessage = function(event) { document.body.innerHTML += "<p>" + event.data + "</p>"; };
                        ws.onclose = function() { document.body.innerHTML += "<p>Disconnected!</p>"; };
                        ws.onerror = function() { document.body.innerHTML += "<p>Error!</p>"; };
                        </script></body></html>)"); });

    server.add_ws_route("/ws").on_open([](network::ws_server_session_base &s)
                                       { s.send("Hello, World!"); })
        .on_message([](network::ws_server_session_base &s, const network::message &msg)
                    { s.send(msg.get_payload()); });

    std::thread t{[&server]
                  { server.start(); }};
    std::this_thread::sleep_for(std::chrono::seconds(20));
    server.stop();
    t.join();
}
#endif

/**
 * @brief Tests the CORS (Cross-Origin Resource Sharing) functionality of the server.
 *
 * This function sets up a server with three routes:
 * - A GET route at "/json" that returns a JSON response with a "Hello, World!" message and allows CORS from any origin.
 * - A POST route at "/json" that returns a JSON response with a "Hello, World!" message and allows CORS from any origin.
 * - An OPTIONS route at "/json" that returns the allowed methods (GET, POST, OPTIONS) and allowed headers (Content-Type) for CORS.
 *
 * The server runs in a separate thread for 5 seconds before stopping.
 */
void test_cors_server()
{
    network::server server;
    server.add_route(network::verb::Get, "/json", [](network::request &)
                     {
                        std::map<std::string, std::string> headers;
                        headers["Access-Control-Allow-Origin"] = "*";
                        return std::make_unique<network::json_response>(json::json{{"message", "Hello, World!"}}, network::ok, std::move(headers)); });

    server.add_route(network::verb::Post, "/json", [](network::request &)
                     {
                        std::map<std::string, std::string> headers;
                        headers["Access-Control-Allow-Origin"] = "*";
                        return std::make_unique<network::json_response>(json::json{{"message", "Hello, World!"}}, network::ok, std::move(headers)); });

    server.add_route(network::verb::Options, "/json", [](network::request &)
                     {
                        std::map<std::string, std::string> headers;
                        headers["Access-Control-Allow-Origin"] = "*";
                        headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS";
                        headers["Access-Control-Allow-Headers"] = "Content-Type";
                        return std::make_unique<network::response>(network::ok, std::move(headers)); });

    std::thread t{[&server]
                  { server.start(); }};
    std::this_thread::sleep_for(std::chrono::seconds(20));
    server.stop();
    t.join();
}

#ifdef ENABLE_CORS
void test_cors_middleware()
{
    network::server server;
    server.add_middleware<network::cors>(server);
    server.add_route(network::verb::Get, "/json", [](network::request &)
                     { return std::make_unique<network::json_response>(json::json{{"message", "Hello, World!"}}); });
    server.add_route(network::verb::Post, "/json", [](network::request &)
                     { return std::make_unique<network::json_response>(json::json{{"message", "Hello, World!"}}); });

    std::thread t{[&server]
                  { server.start(); }};
    std::this_thread::sleep_for(std::chrono::seconds(20));
    server.stop();
    t.join();
}
#endif

int main()
{
    test_rest_server();

#ifdef ENABLE_SSL
    test_ssl_server();
#endif

    test_cors_server();

#ifdef ENABLE_CORS
    test_cors_middleware();
#endif

    return 0;
}
