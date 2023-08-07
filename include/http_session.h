#pragma once

#include "websocket_session.h"

namespace network
{
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
} // namespace network
