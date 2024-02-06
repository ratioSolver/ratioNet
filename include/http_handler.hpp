#pragma once

#include "http_session.hpp"

namespace network
{
  class http_handler
  {
  public:
    virtual ~http_handler() = default;
  };
} // namespace network
