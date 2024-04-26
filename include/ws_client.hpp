#pragma once

#include <queue>
#include "message.hpp"

namespace network
{
  class ws_client
  {
  public:
    ws_client(const std::string &host = SERVER_HOST, unsigned short port = SERVER_PORT);

    void enqueue(std::unique_ptr<message> msg);

  private:
    void connect();

    void write();

    void on_resolve(const boost::system::error_code &ec, boost::asio::ip::tcp::resolver::results_type results);
    void on_connect(const boost::system::error_code &ec);

    void on_write(const boost::system::error_code &ec, std::size_t bytes_transferred);

    void on_read(const boost::system::error_code &ec, std::size_t bytes_transferred);

  private:
    const std::string host;                                             // The host name of the server.
    const unsigned short port;                                          // The port number of the server.
    boost::asio::io_context io_ctx;                                     // The I/O context used for asynchronous operations.
    boost::asio::ip::tcp::resolver resolver;                            // The resolver used to resolve host names.
    boost::asio::ip::tcp::socket socket;                                // The socket used to communicate with the server.
    boost::asio::strand<boost::asio::io_context::executor_type> strand; // The strand used to synchronize access to the queue of requests.
    std::queue<std::unique_ptr<message>> res_queue;                     // The queue of responses to send to the server.
    std::unique_ptr<message> msg;                                       // The current message being processed.
  };
} // namespace network
