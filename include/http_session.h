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

  private:
    server &srv;
    boost::beast::tcp_stream stream;
    boost::beast::flat_buffer buffer;
    boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser;
  };
} // namespace network
