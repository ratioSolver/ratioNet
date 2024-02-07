#pragma once

#include "http_session.hpp"

namespace network
{
  class server_request
  {
  public:
    virtual ~server_request() = default;
  };

  class http_handler
  {
  public:
    virtual ~http_handler() = default;

    virtual void handle_request(server_request &&req) = 0;
  };
} // namespace network
