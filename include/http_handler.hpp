#pragma once

#include "http_session.hpp"

namespace network
{
  class server_request
  {
  public:
    virtual ~server_request() = default;
  };

  template <class Body>
  class server_request_impl : public server_request
  {
  public:
    server_request_impl(boost::beast::http::request<Body> &&req) : req(std::move(req)) {}

    boost::beast::http::request<Body> &get() { return req; }

  private:
    boost::beast::http::request<Body> req;
  };

  class http_handler
  {
  public:
    virtual ~http_handler() = default;

    virtual void handle_request(server_request &&req) = 0;
  };
} // namespace network
