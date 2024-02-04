#pragma once

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <thread>

namespace network
{
  class server;

  class http_session
  {
  public:
    http_session(server &srv, boost::beast::flat_buffer &&buffer) : srv(srv), buffer(std::move(buffer)) {}

    virtual void run() = 0;

  private:
    virtual void do_read() = 0;

  protected:
    server &srv;
    boost::beast::flat_buffer buffer;
  };

  class session_detector
  {
  public:
    session_detector(server &srv, boost::asio::ip::tcp::socket &&socket) : srv(srv), stream(std::move(socket)) {}

    virtual void run() = 0;

  protected:
    server &srv;
    boost::beast::tcp_stream stream;
    boost::beast::flat_buffer buffer;
  };

  class server
  {
  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080, std::size_t concurrency_hint = std::thread::hardware_concurrency());

    void start();

    void stop();

  private:
    virtual void do_accept() = 0;

  protected:
    static std::map<std::string, std::string> parse_query(const std::string &query);

  protected:
    boost::asio::io_context io_ctx;          // The io_context is required for all I/O
    std::vector<std::thread> threads;        // The thread pool
    boost::asio::signal_set signals;         // The signal_set is used to register for process termination notifications
    boost::asio::ip::tcp::endpoint endpoint; // The endpoint for the server
    boost::asio::ip::tcp::acceptor acceptor; // The acceptor receives incoming connections
  };
} // namespace network
