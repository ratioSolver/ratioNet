#pragma once

#include "memory.h"
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/ssl.hpp>
#include <queue>

namespace network
{
  class server;
  template <class Session>
  class request_handler;

  class ssl_http_session
  {
    friend class request_handler<ssl_http_session>;

  public:
    ssl_http_session(server &srv, boost::beast::tcp_stream &&stream, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&buffer, size_t queue_limit = 8);

  private:
    void on_handshake(boost::beast::error_code ec); // Perform the SSL handshake
    void do_read();                                 // Start reading a request

    void on_read(boost::beast::error_code ec, std::size_t bytes_transferred);
    void on_write(boost::beast::error_code ec, std::size_t bytes_transferred, bool close);

    void do_eof();
    void on_shutdown(boost::beast::error_code ec);

  private:
    server &srv;
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream;
    boost::beast::flat_buffer buffer;
    boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser;
    const size_t queue_limit;                                               // The limit on the allowed size of the queue
    std::queue<utils::u_ptr<request_handler<ssl_http_session>>> work_queue; // This queue is used for the work that is to be done on the session
  };
} // namespace network
