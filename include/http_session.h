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
    server &srv;
    boost::beast::tcp_stream stream;
    boost::beast::flat_buffer buffer;
  };
} // namespace network
