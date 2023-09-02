#include "server.h"

void test_simple()
{
  network::server server;

  server.add_route(boost::beast::http::verb::get, "/", std::function{[](const boost::beast::http::request<boost::beast::http::string_body> &, boost::beast::http::response<boost::beast::http::string_body> &res)
                                                                     {
                                                                       res.set(boost::beast::http::field::content_type, "html");
                                                                       res.body() = R"(<html><body><h1>Hello, world!</h1></body></html>)";
                                                                     }});

  auto t = new std::thread{[&server]
                           { server.start(); }};

  std::this_thread::sleep_for(std::chrono::seconds(10));
  server.stop();
  t->join();
  delete t;
}

void test_ssl()
{
  network::server server;

  server.set_ssl_context("cert.pem", "key.pem", "dh.pem");

  server.add_route(boost::beast::http::verb::get, "/", std::function{[](const boost::beast::http::request<boost::beast::http::string_body> &, boost::beast::http::response<boost::beast::http::string_body> &res)
                                                                     {
                                                                       res.set(boost::beast::http::field::content_type, "html");
                                                                       res.body() = R"(<html><body><h1>Hello, world!</h1></body></html>)";
                                                                     }},
                   true);

  auto t = new std::thread{[&server]
                           { server.start(); }};

  std::this_thread::sleep_for(std::chrono::seconds(1000));
  server.stop();
  t->join();
  delete t;
}

int main()
{
  // test_simple();

  test_ssl();

  return 0;
}
