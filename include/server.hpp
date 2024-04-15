#pragma once

#include <boost/asio.hpp>

namespace network
{
  enum verb
  {
    GET,
    POST,
    PUT,
    DELETE
  };

  class session : public std::enable_shared_from_this<session>
  {
  public:
    session(boost::asio::ip::tcp::socket socket);
    ~session();

    void start();

  private:
    void on_read(const boost::system::error_code &ec, std::size_t bytes_transferred);

  private:
    boost::asio::ip::tcp::socket socket;
    boost::asio::streambuf buffer;
  };

  class server
  {
  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080, std::size_t concurrency_hint = std::thread::hardware_concurrency());

    /**
     * @brief Start the server.
     */
    void start();

  private:
    void do_accept();
    void on_accept(const boost::system::error_code &ec, boost::asio::ip::tcp::socket socket);

  private:
    boost::asio::io_context io_ctx;          // The io_context is required for all I/O
    std::vector<std::thread> threads;        // The thread pool
    boost::asio::ip::tcp::endpoint endpoint; // The endpoint for the server
    boost::asio::ip::tcp::acceptor acceptor; // The acceptor for the server
  };
} // namespace network
