#pragma once

#include "memory.h"
#include <boost/beast.hpp>
#include <regex>

namespace network
{
  using method = boost::beast::http::verb;
  using request = boost::beast::http::request<boost::beast::http::dynamic_body>;
  using response = boost::beast::http::response<boost::beast::http::string_body>;
  using websocket = boost::beast::websocket::stream<boost::asio::ip::tcp::socket>;

  class server
  {
  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080);

    void start();

  private:
    void on_accept(boost::system::error_code ec);

  private:
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::socket socket;
  };
} // namespace network
