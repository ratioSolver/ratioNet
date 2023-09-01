#include "server.h"

int main()
{
  network::server server("0.0.0.0", 443);

  server.add_route(boost::beast::http::verb::get, "/", std::function{[](const boost::beast::http::request<boost::beast::http::string_body> &, boost::beast::http::response<boost::beast::http::string_body> &res)
                                                                     {
                                                                       res.set(boost::beast::http::field::content_type, "html");
                                                                       res.body() = R"(<html><body><h1>Hello, world!</h1></body></html>)";
                                                                     }});

  server.add_route(boost::beast::http::verb::get, "/", std::function{[](const boost::beast::http::request<boost::beast::http::string_body> &, boost::beast::http::response<boost::beast::http::string_body> &res)
                                                                     {
                                                                       res.set(boost::beast::http::field::content_type, "html");
                                                                       res.body() = R"(<html><body><h1>Hello, world!</h1></body></html>)";
                                                                     }},
                   true);

  server.start();

  return 0;
}
