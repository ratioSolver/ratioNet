#pragma once

#include "memory.h"
#include <boost/beast.hpp>
#include <queue>

namespace network
{
  class server;
  class websocket_session;

  class message final : public utils::countable
  {
    friend class websocket_session;

  public:
    message(const std::string &msg) : msg(msg) {}
    message(const std::string &&msg) : msg(std::move(msg)) {}

  private:
    std::string msg;
  };

  class websocket_session
  {
    friend class server;

  public:
    websocket_session(server &srv, boost::asio::ip::tcp::socket &&socket);
    ~websocket_session();

    void run(boost::beast::http::request<boost::beast::http::string_body> req);

    void send(const std::string &&msg) { send(utils::c_ptr<message>(new message(std::move(msg)))); }

  private:
    void send(utils::c_ptr<message> msg);

    void on_accept(boost::system::error_code ec);
    void on_read(boost::system::error_code ec, std::size_t bytes_transferred);
    void on_write(boost::system::error_code ec, std::size_t bytes_transferred);

  private:
    server &srv;
    boost::beast::flat_buffer buffer;
    boost::beast::websocket::stream<boost::beast::tcp_stream> ws;
    std::queue<utils::c_ptr<message>> send_queue;
  };
} // namespace network
