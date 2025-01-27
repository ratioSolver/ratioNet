#pragma once

#include "memory.hpp"
#include "message.hpp"
#include <queue>

namespace network
{
  class ws_client
  {
  public:
    ws_client(const std::string &host = SERVER_HOST, unsigned short port = SERVER_PORT);

    void enqueue(utils::u_ptr<message> msg);

  private:
    void connect();

    void write();

    void on_resolve(const std::error_code &ec, asio::ip::tcp::resolver::results_type results);
    void on_connect(const std::error_code &ec);

    void on_write(const std::error_code &ec, std::size_t bytes_transferred);

    void on_read(const std::error_code &ec, std::size_t bytes_transferred);

  private:
    const std::string host;                               // The host name of the server.
    const unsigned short port;                            // The port number of the server.
    asio::io_context io_ctx;                              // The I/O context used for asynchronous operations.
    asio::ip::tcp::resolver resolver;                     // The resolver used to resolve host names.
    asio::ip::tcp::socket socket;                         // The socket used to communicate with the server.
    asio::strand<asio::io_context::executor_type> strand; // The strand used to synchronize access to the queue of requests.
    std::queue<utils::u_ptr<message>> res_queue;          // The queue of responses to send to the server.
    utils::u_ptr<message> msg;                            // The current message being processed.
  };
} // namespace network
