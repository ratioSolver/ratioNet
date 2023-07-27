#pragma once

#include "message.h"
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <queue>

namespace network
{
  class websocket_client
  {
  public:
    websocket_client(const std::string &host, const std::string &service = "80", const std::string &path = "/");

    websocket_client &on_open(std::function<void()> handler) noexcept
    {
      on_open_handler = handler;
      return *this;
    }
    websocket_client &on_message(std::function<void(std::string)> handler) noexcept
    {
      on_message_handler = handler;
      return *this;
    }
    websocket_client &on_error(std::function<void(boost::system::error_code)> handler) noexcept
    {
      on_error_handler = handler;
      return *this;
    }
    websocket_client &on_close(std::function<void()> handler) noexcept
    {
      on_close_handler = handler;
      return *this;
    }

    void start();

    void send(message_ptr msg);

    void close(boost::beast::websocket::close_code code = boost::beast::websocket::close_code::normal);

  private:
    void on_resolve(boost::system::error_code ec, boost::asio::ip::tcp::resolver::results_type results);
    void on_connect(boost::system::error_code ec, boost::asio::ip::tcp::resolver::results_type::endpoint_type endpoint);
    void on_handshake(boost::system::error_code ec);
    void on_send(message_ptr msg);
    void on_write(boost::system::error_code ec, std::size_t bytes_transferred);
    void on_read(boost::system::error_code ec, std::size_t bytes_transferred);
    void on_close(boost::system::error_code ec);

  private:
    std::string host;
    std::string path;
    boost::asio::io_context io_context;
    boost::asio::signal_set signals;
    boost::asio::ip::tcp::resolver resolver;
    boost::beast::flat_buffer buffer;
    boost::beast::websocket::stream<boost::beast::tcp_stream> ws;
    std::queue<message_ptr> send_queue;
    std::function<void()> on_open_handler = []() {};
    std::function<void(std::string)> on_message_handler = [](std::string) {};
    std::function<void()> on_close_handler = []() {};
    std::function<void(boost::system::error_code)> on_error_handler = [](boost::system::error_code) {};
  };
} // namespace network
