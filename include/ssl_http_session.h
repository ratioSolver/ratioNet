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
    server &srv;
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream;
    boost::beast::flat_buffer buffer;
  };
} // namespace network
