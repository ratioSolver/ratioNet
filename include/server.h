#pragma once

#include "http_session.h"
#include <thread>
#include <boost/asio.hpp>
#ifdef USE_SSL
#include <boost/beast/ssl.hpp>
#include <boost/asio/ssl.hpp>
#endif

namespace network
{
#ifdef USE_SSL
  /**
   * @brief Detects the session type.
   */
  class session_detector
  {
  public:
    session_detector(boost::asio::ip::tcp::socket &&socket, boost::asio::ssl::context &ctx);

    void run();

  private:
    void on_run();
    void on_detect(boost::system::error_code ec, bool result);

  private:
    boost::beast::flat_buffer buffer;
    boost::beast::tcp_stream stream;
    boost::asio::ssl::context &ctx;
  };
#endif

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
    void on_accept(boost::system::error_code ec, boost::asio::ip::tcp::socket socket);

  private:
    std::size_t thread_pool_size;     // The number of threads in the thread pool.
    std::vector<std::thread> threads; // The thread pool.

    boost::asio::io_context ioc; // The io_context is required for all I/O.
#ifdef USE_SSL
    boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12}; // The SSL context is required, and holds certificates.
#endif

    boost::asio::signal_set signals;         // The signal_set is used to register for process termination notifications.
    boost::asio::ip::tcp::acceptor acceptor; // The acceptor object used to accept incoming socket connections.
  };
} // namespace network
