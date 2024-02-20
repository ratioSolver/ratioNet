#pragma once

#include <boost/asio.hpp>
#include <boost/beast.hpp>

namespace network
{
  class base_http_session
  {
  };

  class http_session : public base_http_session
  {
  };
} // namespace network
