#include "server.hpp"

using string_req = boost::beast::http::request<boost::beast::http::string_body>;
using string_res = boost::beast::http::response<boost::beast::http::string_body>;

void test_plain()
{
  network::server server;

  server.add_route(boost::beast::http::verb::get, "/", std::function{[](const string_req &, string_res &res)
                                                                     {
                                                                       res.set(boost::beast::http::field::content_type, "html");
                                                                       res.body() = R"(<html><body><h1>Hello, world!</h1></body></html>)";
                                                                     }});

  std::thread t{[&server]
                { server.start(); }};

  std::this_thread::sleep_for(std::chrono::seconds(10));
  server.stop();
  t.join();
}

void test_ssl()
{
  network::server server;

  server.set_ssl_context("cert.pem", "key.pem", "dh.pem");

  server.add_route(boost::beast::http::verb::get, "/", std::function{[](const string_req &, string_res &res)
                                                                     {
                                                                       res.set(boost::beast::http::field::content_type, "html");
                                                                       res.body() = R"(<html><body><h1>Hello, world!</h1></body></html>)";
                                                                     }},
                   true);

  std::thread t{[&server]
                { server.start(); }};

  std::this_thread::sleep_for(std::chrono::seconds(10));
  server.stop();
  t.join();
}

void test_websocket()
{
  network::server server;

  server.add_route(boost::beast::http::verb::get, "/", std::function{[](const string_req &, string_res &res)
                                                                     {
                                                                       res.set(boost::beast::http::field::content_type, "html");
                                                                       res.body() = R"(
                                                                        <html>
                                                                        <body>
                                                                        <h1>Hello, world!</h1>
                                                                        <script>
                                                                        var ws = new WebSocket("ws://" + window.location.host + "/ws");
                                                                        ws.onmessage = function(event) {
                                                                          alert("Message from server: " + event.data);
                                                                        };
                                                                        </script>
                                                                        </body>
                                                                        </html>)";
                                                                     }});

  server.add_ws_route("/ws").on_open([](network::websocket_session &session)
                                     { session.send("Hello, world!"); });

  std::thread t{[&server]
                { server.start(); }};

  std::this_thread::sleep_for(std::chrono::seconds(10));
  server.stop();
  t.join();
}

int main()
{
  test_plain();

  test_ssl();

  test_websocket();

  return 0;
}
