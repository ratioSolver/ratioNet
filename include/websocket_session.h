#pragma once

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>

namespace network
{
  class websocket_session
  {
  public:
    websocket_session(boost::asio::ip::tcp::socket &&socket) : ws(std::move(socket)) {}

  private:
    void on_read(boost::system::error_code ec, size_t);
    void on_write(boost::system::error_code ec, size_t bytes_transferred);

  protected:
    boost::beast::flat_buffer buffer;
    boost::beast::websocket::stream<boost::beast::tcp_stream> ws;
  };
} // namespace network
