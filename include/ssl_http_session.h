#pragma once

#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/ssl.hpp>

namespace network
{
  class server;

  class ssl_http_session
  {
  public:
    ssl_http_session(server &srv, boost::beast::tcp_stream &&stream, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&buffer);

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
  };
} // namespace network
