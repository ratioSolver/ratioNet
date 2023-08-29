#pragma once

#include <boost/beast.hpp>

namespace network
{
  class http_session
  {
  public:
    http_session(boost::beast::tcp_stream &&stream, boost::beast::flat_buffer &&buffer);

  private:
    boost::beast::tcp_stream stream;
    boost::beast::flat_buffer buffer;
  };
} // namespace network
