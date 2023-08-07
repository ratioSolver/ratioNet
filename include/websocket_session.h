#pragma once

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include "logging.h"

namespace network
{
  template <class Derived>
  class websocket_session
  {
    Derived &derived() { return static_cast<Derived &>(*this); }

  public:
    template <class Body, class Allocator>
    void run(boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>> req)
    {
      do_accept(std::move(req));
    }

    // Start the asynchronous operation
    template <class Body, class Allocator>
    void do_accept(boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>> req)
    {
    }

    void on_accept(boost::system::error_code ec)
    {
    }

    void do_read()
    {
    }

    void on_read(boost::system::error_code ec, size_t)
    {
    }

    void on_write(boost::system::error_code ec, size_t bytes_transferred)
    {
    }

  protected:
    boost::beast::flat_buffer buffer;
  };
} // namespace network
