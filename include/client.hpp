#pragma once

#include <queue>
#include "request.hpp"
#include "response.hpp"

namespace network
{
  class client
  {
  public:
    client(const std::string &host = SERVER_HOST, unsigned short port = SERVER_PORT);

    void enqueue(std::unique_ptr<request> req);

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
    std::queue<std::unique_ptr<request>> req_queue;                     // The queue of requests to send to the server.
    std::unique_ptr<response> res;                                      // The current response being processed.
  };
} // namespace network
