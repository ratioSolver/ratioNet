#pragma once

#include <boost/beast.hpp>

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

  class response
  {
  public:
    virtual ~response() = default;
  };

  template <class Session, class Body>
  class response_impl : public response
  {
  public:
    response_impl(Session &session, boost::beast::http::response<Body> &&res) : session(session), res(std::move(res)) {}

    Session &get_session() { return session; }
    boost::beast::http::response<Body> &get_response() { return res; }

  public:
    Session &session;
    boost::beast::http::response<Body> res;
  };
} // namespace network
