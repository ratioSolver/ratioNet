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
    void run(boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>> req) { do_accept(std::move(req)); }

    // Start the asynchronous operation
    template <class Body, class Allocator>
    void do_accept(boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>> req)
    {
      derived().get_stream().set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::server));

      derived().get_stream().set_option(boost::beast::websocket::stream_base::decorator([](boost::beast::websocket::response_type &res)
                                                                                        { res.set(boost::beast::http::field::server, std::string(BOOST_BEAST_VERSION_STRING)); }));

      derived().get_stream().async_accept(req, [this](boost::system::error_code ec)
                                          { on_accept(ec); });
    }

    void on_accept(boost::system::error_code ec)
    {
      if (ec)
      {
        LOG_ERR("Error: " << ec.message() << "\n");
        delete this;
        return;
      }

      // Read a message
      do_read();
    }

    void do_read()
    {
      derived().get_stream().async_read(buffer, [this](boost::system::error_code ec, size_t bytes_transferred)
                                        { on_read(ec, bytes_transferred); });
    }

    void on_read(boost::system::error_code ec, size_t)
    {
      if (ec == boost::beast::websocket::error::closed)
      {
        delete this;
        return;
      }

      if (ec)
      {
        LOG_ERR("Error: " << ec.message() << "\n");
        delete this;
        return;
      }

      derived().get_stream().async_read(buffer, [this](boost::system::error_code ec, size_t bytes_transferred)
                                        { on_read(ec, bytes_transferred); });
    }

    void on_write(boost::system::error_code ec, size_t bytes_transferred)
    {
      if (ec)
      {
        LOG_ERR("Error: " << ec.message() << "\n");
        delete this;
        return;
      }

      buffer.consume(buffer.size());

      do_read();
    }

  protected:
    boost::beast::flat_buffer buffer;
  };

  class plain_websocket_session : public websocket_session<plain_websocket_session>
  {
  public:
    plain_websocket_session(boost::beast::tcp_stream &&stream) : ws(std::move(stream)) {}

    boost::beast::websocket::stream<boost::beast::tcp_stream> &get_stream() { return ws; }

  private:
    boost::beast::websocket::stream<boost::beast::tcp_stream> ws;
  };

  class ssl_websocket_session : public websocket_session<ssl_websocket_session>
  {
  public:
    ssl_websocket_session(boost::beast::ssl_stream<boost::beast::tcp_stream> &&stream) : ws(std::move(stream)) {}

    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>> &get_stream() { return ws; }

  private:
    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>> ws;
  };

  template <class Body, class Allocator>
  void make_websocket_session(boost::beast::tcp_stream stream, boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>> req) { (new plain_websocket_session(std::move(stream)))->run(std::move(req)); }

  template <class Body, class Allocator>
  void make_websocket_session(boost::beast::ssl_stream<boost::beast::tcp_stream> stream, boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>> req) { (new ssl_websocket_session(std::move(stream)))->run(std::move(req)); }
} // namespace network
