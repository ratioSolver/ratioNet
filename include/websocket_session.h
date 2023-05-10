#pragma once

#include "memory.h"
#include <boost/beast.hpp>
#include <queue>

namespace network
{
  class server;

  class websocket_session
  {
  public:
    websocket_session(server &srv, boost::asio::ip::tcp::socket &&socket);
    ~websocket_session();

    void run(boost::beast::http::request<boost::beast::http::string_body> req);

    void send(const std::string &&message);

  private:
    void on_accept(boost::system::error_code ec);
    void on_read(boost::system::error_code ec, std::size_t bytes_transferred);
    void on_write(boost::system::error_code ec, std::size_t bytes_transferred);

  private:
    server &srv;
    boost::beast::flat_buffer buffer;
    boost::beast::websocket::stream<boost::beast::tcp_stream> ws;
    std::queue<utils::u_ptr<std::string>> send_queue;
  };
} // namespace network
