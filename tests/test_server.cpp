#include "server.h"

int main()
{
  network::server server;

/*
  server.add_route(
      boost::beast::http::verb::get,
      "/",
      [](boost::beast::http::request<boost::beast::http::string_body> &req, boost::beast::http::response<boost::beast::http::string_body> &res)
      {
        res.body() = "Hello, world!";
        res.prepare_payload();
      });
*/

  server.start();

  return 0;
}
