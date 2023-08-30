#pragma once

#include "memory.h"
#include <boost/beast/http.hpp>

namespace network
{
  class request
  {
  public:
    virtual ~request() = default;

    virtual boost::string_view get_target() const noexcept = 0;
    virtual boost::beast::http::verb get_method() const noexcept = 0;
    virtual unsigned get_version() const noexcept = 0;
    virtual bool keep_alive() const noexcept = 0;
  };
  using request_ptr = utils::u_ptr<request>;

  template <class Body, class Fields>
  class request_impl : public request
  {
  public:
    request_impl(boost::beast::http::request<Body, Fields> &&req) : req(std::move(req)) {}

    boost::string_view get_target() const noexcept { return req.target(); }
    boost::beast::http::verb get_method() const noexcept { return req.method(); }
    unsigned get_version() const noexcept { return req.version(); }
    bool keep_alive() const noexcept { return req.keep_alive(); }

    boost::beast::http::request<Body, Fields> req;
  };
} // namespace network
