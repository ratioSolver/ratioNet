#pragma once

#include "http_session.h"
#include <thread>
#include <boost/asio.hpp>

namespace network
{
  /**
   * @brief A server.
   */
  class server
  {
  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080, std::size_t thread_pool_size = std::thread::hardware_concurrency());

    /**
     * @brief Run the server.
     */
    void start();

    /**
     * @brief Stop the server.
     */
    void stop();

  private:
    std::size_t thread_pool_size;     // The number of threads in the thread pool.
    std::vector<std::thread> threads; // The thread pool.

    boost::asio::io_context ioc;             // The io_context is required for all I/O.
    boost::asio::signal_set signals;         // The signal_set is used to register for process termination notifications.
    boost::asio::ip::tcp::acceptor acceptor; // The acceptor object used to accept incoming socket connections.
  };
} // namespace network
