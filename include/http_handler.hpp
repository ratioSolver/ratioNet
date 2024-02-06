#pragma once

#include "http_session.hpp"

namespace network
{
  class http_handler
  {
  public:
    virtual ~http_handler() = default;

    template <class Body>
    void handle_request(boost::beast::http::request<Body> &&req) {}
  };
} // namespace network
