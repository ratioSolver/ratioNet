#pragma once

#include <boost/beast.hpp>

namespace network
{
  class server;

  class http_session
  {
  public:
    http_session(server &srv, boost::beast::tcp_stream &&stream, boost::beast::flat_buffer &&buffer);

  private:
    void do_read(); // Start reading a request

    void on_read(boost::beast::error_code ec, std::size_t bytes_transferred);
    void on_write(boost::beast::error_code ec, std::size_t bytes_transferred, bool close);

    void do_eof();

  private:
    server &srv;
    boost::beast::tcp_stream stream;
    boost::beast::flat_buffer buffer;
    boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser;
  };
} // namespace network
