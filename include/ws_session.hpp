#pragma once

#include <queue>
#include "message.hpp"

namespace network
{
  class server;
  class session;

  class ws_session : public std::enable_shared_from_this<ws_session>
  {
    friend class server;
    friend class session;

  public:
    ws_session(server &srv, boost::asio::ip::tcp::socket &&socket);
    ~ws_session();

    void enqueue(std::unique_ptr<message> res);
    void ping() { enqueue(std::make_unique<message>(0x89)); }
    void pong() { enqueue(std::make_unique<message>(0x8A)); }
    void close() { enqueue(std::make_unique<message>(0x88)); }

  private:
    void read();
    void write();

    void on_read(const boost::system::error_code &ec, std::size_t bytes_transferred);
    void on_message(const boost::system::error_code &ec, std::size_t bytes_transferred);

    void on_write(const boost::system::error_code &ec, std::size_t bytes_transferred);

  private:
    server &srv;                                    // reference to the server
    boost::asio::ip::tcp::socket socket;            // socket for the session
    std::unique_ptr<message> msg;                   // message being read
    std::queue<std::unique_ptr<message>> res_queue; // queue for the responses
  };
} // namespace network
