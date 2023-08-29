#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <functional>
#include <regex>
#include <thread>

namespace network
{
  class http_work;
  class ssl_http_session;

  /**
   * @brief The server class.
   */
  class server
  {
    friend class http_work;
    friend class ssl_http_session;

  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080, std::size_t concurrency_hint = std::thread::hardware_concurrency());

    /**
     * @brief Start the server.
     */
    void start();
    /**
     * @brief Stop the server.
     */
    void stop();

    void set_ssl_context(const std::string &certificate_chain_file, const std::string &private_key_file, const std::string &dh_file);

  private:
    void on_accept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket);

    template <class Session, class Body, class Fields>
    void handle_request(Session &session, boost::beast::http::request<Body, Fields> &&req);

  private:
    boost::asio::io_context ioc;                                      // The io_context is required for all I/O
    std::vector<std::thread> threads;                                 // The thread pool
    boost::asio::signal_set signals;                                  // The signal_set is used to register for process termination notifications
    boost::asio::ip::tcp::endpoint endpoint;                          // The endpoint for the server
    boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12}; // The SSL context is required, and holds certificates
    boost::asio::ip::tcp::acceptor acceptor;                          // The acceptor receives incoming connections
  };
} // namespace network
