#include "server.h"

int main()
{
  network::server server;

  std::function<void(const boost::beast::http::request<boost::beast::http::string_body> &, boost::beast::http::response<boost::beast::http::string_body> &)> handler = [](const boost::beast::http::request<boost::beast::http::string_body> &req, boost::beast::http::response<boost::beast::http::string_body> &res)
  {
    res.body() = "Hello, world!";
    res.prepare_payload();
  };

  server.add_route(boost::beast::http::verb::get, "/", handler);

  server.start();

  return 0;
}
