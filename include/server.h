#pragma once

#include "websocket_session.h"
#include "http_session.h"

namespace network
{
  class detector
  {
  public:
    detector(boost::asio::ip::tcp::socket &&socket, boost::asio::ssl::context &ctx);

    void run();

  private:
    void on_run();
    void on_detect(boost::system::error_code ec, bool result);

    boost::beast::tcp_stream stream;
    boost::asio::ssl::context &ctx;
    boost::beast::flat_buffer buffer;
  };

  /**
   * @brief A server.
   */
  class server
  {
  public:
    server(boost::asio::io_context &ioc, boost::asio::ip::tcp::endpoint endpoint);

    void run();

  private:
    void do_accept();
    void on_accept(boost::system::error_code ec);

    boost::asio::io_context &ioc;
    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::socket socket;
    boost::beast::flat_buffer buffer;
  };
} // namespace network
