#pragma once

#include "http_session.hpp"

namespace network
{
  class request
  {
  public:
    virtual ~request() = default;
  };

  template <class Session, class Body>
  class request_impl : public request
  {
  public:
    request_impl(Session &session, boost::beast::http::request<Body> &&req) : session(session), req(std::move(req)) {}

    Session &get_session() { return session; }
    boost::beast::http::request<Body> &get_request() { return req; }

  private:
    Session &session;
    boost::beast::http::request<Body> req;
  };

  class http_handler
  {
  public:
    virtual ~http_handler() = default;

    virtual void handle_request(request &&req) = 0;
  };
} // namespace network
