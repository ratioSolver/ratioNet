#pragma once

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#ifdef USE_SSL
#include <boost/beast/ssl.hpp>
#endif

namespace network
{
  /**
   * @brief Base class for HTTP sessions.
   *
   */
  class http_session
  {
  public:
    http_session(boost::beast::flat_buffer buffer) : buffer(std::move(buffer)) {}
    virtual ~http_session() = default;

    void run();

  private:
    void on_read(boost::system::error_code ec, size_t bytes_transferred);
    void on_write(boost::system::error_code ec, size_t bytes_transferred, bool close);

  private:
    boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser;

  protected:
    boost::beast::flat_buffer buffer;
  };

  /**
   * @brief HTTP session for a WebSocket connection.
   *
   */
  class plain_http_session : public http_session
  {
  public:
    plain_http_session(boost::beast::tcp_stream &&stream, boost::beast::flat_buffer &&buffer);

  private:
    boost::beast::tcp_stream stream;
  };

#ifdef USE_SSL
  /**
   * @brief HTTP session for a WebSocket connection.
   *
   */
  class ssl_http_session : public http_session
  {
  public:
    ssl_http_session(boost::beast::ssl_stream<boost::beast::tcp_stream> &&stream, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&buffer);

  private:
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream;
  };
#endif
} // namespace network
