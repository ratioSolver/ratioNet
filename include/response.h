#pragma once

#include "http_session.h"
#include "ssl_http_session.h"
#include <boost/beast/http.hpp>

namespace network
{
  class response
  {
    friend class request_handler;
    friend class ssl_request_handler;

  public:
    virtual ~response() = default;

  private:
    virtual void handle_response(http_session &session) = 0;
    virtual void handle_response(ssl_http_session &session) = 0;
  };
  using response_ptr = utils::u_ptr<response>;

  template <class Body, class Fields>
  class response_impl : public response
  {
    friend class request_handler;
    friend class ssl_request_handler;
    friend class http_session;
    friend class ssl_http_session;

  public:
    response_impl(boost::beast::http::response<Body, Fields> &&res) : res(std::move(res)) {}
    virtual ~response_impl() = default;

  private:
    void handle_response(http_session &session) override
    {
      res.set(boost::beast::http::field::server, "ratioNet");
      res.prepare_payload();
      boost::beast::http::async_write(session.stream, res, [this, &session](boost::beast::error_code ec, std::size_t bytes_transferred)
                                      { session.on_write(ec, bytes_transferred, res.need_eof()); });
    }
    void handle_response(ssl_http_session &session) override
    {
      res.set(boost::beast::http::field::server, "ratioNet");
      res.prepare_payload();
      boost::beast::http::async_write(session.stream, res, [this, &session](boost::beast::error_code ec, std::size_t bytes_transferred)
                                      { session.on_write(ec, bytes_transferred, res.need_eof()); });
    }

  private:
    boost::beast::http::response<Body, Fields> res;
  };
} // namespace network
