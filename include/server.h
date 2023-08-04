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

  /**
   * @brief Base class for HTTP sessions.
   *
   * @tparam Derived The derived class.
   */
  template <class Derived>
  class http_session
  {
    Derived &derived() { return static_cast<Derived &>(*this); }

  public:
    http_session(boost::beast::flat_buffer buffer) : buffer(std::move(buffer)) {}

  protected:
    void do_read()
    {
      derived().parser.emplace();
      derived().parser->body_limit(1000000);
      boost::beast::get_lowest_layer(derived().get_stream()).expires_after(std::chrono::seconds(30));
      boost::beast::http::async_read(derived().get_stream(), derived().buffer, *parser, [this](boost::system::error_code ec, size_t bytes_transferred)
                                     { on_read(ec, bytes_transferred); });
    }

  private:
    void on_read(boost::system::error_code ec, [[maybe_unused]] size_t bytes_transferred)
    {
      if (ec == boost::beast::http::error::end_of_stream)
        return derived().do_eof();

      if (ec)
      {
        LOG_ERR("Error: " << ec.message() << "\n");
        delete this;
        return;
      }

      if (boost::beast::websocket::is_upgrade(parser->get()))
      {
        boost::beast::get_lowest_layer(derived().get_stream()).expires_never();

        make_websocket_session(derived().release_stream(), parser->release());
      }
    }

  private:
    boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser;

  protected:
    boost::beast::flat_buffer buffer;
  };

  /**
   * @brief A plain HTTP session.
   */
  class plain_http_session : public http_session<plain_http_session>
  {
  public:
    plain_http_session(boost::beast::tcp_stream &&stream, boost::beast::flat_buffer &&buffer);

    boost::beast::tcp_stream &get_stream() { return stream; }
    boost::beast::tcp_stream release_stream() { return std::move(stream); }

    void run();

    void do_eof();

  private:
    boost::beast::tcp_stream stream;
  };

  /**
   * @brief An SSL HTTP session.
   */
  class ssl_http_session : public http_session<ssl_http_session>
  {
  public:
    ssl_http_session(boost::beast::tcp_stream &&stream, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&buffer);

    boost::beast::ssl_stream<boost::beast::tcp_stream> &get_stream() { return stream; }
    boost::beast::ssl_stream<boost::beast::tcp_stream> release_stream() { return std::move(stream); }

    void run();

    void do_eof();

  private:
    void on_handshake(boost::system::error_code ec, size_t bytes_transferred);
    void on_shutdown(boost::system::error_code ec);

  private:
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream;
  };

  class detector
  {
  public:
    detector(boost::asio::ip::tcp::socket &&socket, boost::asio::ssl::context &ctx);

    void run();

  private:
    void on_run();
    void on_detect(boost::system::error_code ec, bool result);

    boost::beast::tcp_stream stream;
    boost::asio::ssl::context &ctx;
    boost::beast::flat_buffer buffer;
  };

  /**
   * @brief A server.
   */
  class server
  {
  public:
    server(boost::asio::io_context &ioc, boost::asio::ip::tcp::endpoint endpoint);

    void run();

  private:
    void do_accept();
    void on_accept(boost::system::error_code ec);

    boost::asio::io_context &ioc;
    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::socket socket;
    boost::beast::flat_buffer buffer;
  };
} // namespace network
