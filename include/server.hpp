#pragma once

#include "session.hpp"

namespace network
{
  class server
  {
    friend class session;

  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080, std::size_t concurrency_hint = std::thread::hardware_concurrency());
    ~server();

    /**
     * @brief Start the server.
     */
    void start();

    /**
     * @brief Stop the server.
     */
    void stop();

  private:
    void do_accept();
    void on_accept(const boost::system::error_code &ec, boost::asio::ip::tcp::socket socket);

    void handle_request(std::unique_ptr<request> req);

  private:
    boost::asio::io_context io_ctx;          // The io_context is required for all I/O
    std::vector<std::thread> threads;        // The thread pool
    boost::asio::ip::tcp::endpoint endpoint; // The endpoint for the server
    boost::asio::ip::tcp::acceptor acceptor; // The acceptor for the server
  };
} // namespace network
