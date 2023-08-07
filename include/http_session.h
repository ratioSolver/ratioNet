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

    void run() {}

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

  private:
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream;
  };
} // namespace network
