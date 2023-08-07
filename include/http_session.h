#pragma once

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>

namespace network
{
  /**
   * @brief Base class for HTTP sessions.
   *
   */
  template <class Derived>
  class http_session
  {
  public:
    http_session(boost::beast::flat_buffer buffer) : buffer(std::move(buffer)) {}

    Derived &derived() { return static_cast<Derived &>(*this); }

    void do_read()
    {
      // Make the request empty before reading,
      // otherwise the operation behavior is undefined.
      parser.emplace();

      boost::beast::get_lowest_layer(derived().get_stream()).expires_after(std::chrono::seconds(30));

      // Set the timeout.
      boost::beast::get_lowest_layer(derived().get_stream()).expires_after(std::chrono::seconds(30));

      // Read a request
      boost::beast::http::async_read(derived().get_stream(), buffer, *parser, [this](boost::system::error_code ec, size_t bytes_transferred)
                                     { on_read(ec, bytes_transferred); });
    }

  private:
    void on_read(boost::system::error_code ec, size_t bytes_transferred) {}
    void on_write(boost::system::error_code ec, size_t bytes_transferred, bool close) {}

  private:
    boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser;

  protected:
    boost::beast::flat_buffer buffer;
  };

  /**
   * @brief HTTP session for a WebSocket connection.
   *
   */
  class plain_http_session : public http_session<plain_http_session>
  {
  public:
    plain_http_session(boost::beast::tcp_stream &&stream, boost::beast::flat_buffer &&buffer);

    void run();

    boost::beast::tcp_stream &get_stream() { return stream; }

  private:
    boost::beast::tcp_stream stream;
  };

  /**
   * @brief HTTP session for a WebSocket connection.
   *
   */
  class ssl_http_session : public http_session<ssl_http_session>
  {
  public:
    ssl_http_session(boost::beast::tcp_stream &&stream, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&buffer);

    void run();

    boost::beast::ssl_stream<boost::beast::tcp_stream> &get_stream() { return stream; }

  private:
    void on_handshake(boost::system::error_code ec, size_t bytes_used);

  private:
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream;
  };
} // namespace network
