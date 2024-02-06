#pragma once

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#ifdef USE_SSL
#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>
#endif

namespace network
{
  class server;
  class http_handler;
  class websocket_handler;

  class http_session
  {
  public:
    http_session(server &srv, boost::beast::flat_buffer &&buffer) : srv(srv), buffer(std::move(buffer)) {}

    virtual void run() = 0;
    virtual void do_eof() = 0;

  protected:
    boost::optional<http_handler &> get_http_handler(boost::beast::http::verb method, const std::string &target);
    boost::optional<websocket_handler &> get_ws_handler(const std::string &target);
#ifdef USE_SSL
    boost::optional<http_handler &> get_https_handler(boost::beast::http::verb method, const std::string &target);
    boost::optional<websocket_handler &> get_wss_handler(const std::string &target);
#endif

  protected:
    server &srv;
    boost::beast::flat_buffer buffer;
    boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser;
  };

  class plain_session : public http_session
  {
  public:
    plain_session(server &srv, boost::beast::tcp_stream &&str, boost::beast::flat_buffer &&buffer) : http_session(srv, std::move(buffer)), stream(std::move(str)) {}

  protected:
    boost::beast::tcp_stream stream;
  };

#ifdef USE_SSL
  class ssl_session : public http_session
  {
  public:
    ssl_session(server &srv, boost::beast::tcp_stream &&str, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&buffer) : http_session(srv, std::move(buffer)), stream(std::move(str), ctx) {}

  protected:
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream;
  };

  class session_detector
  {
  public:
    session_detector(server &srv, boost::asio::ip::tcp::socket &&socket, boost::asio::ssl::context &ctx) : srv(srv), stream(std::move(socket)), ctx(ctx) {}

    virtual void run() = 0;

  protected:
    server &srv;
    boost::beast::tcp_stream stream;
    boost::asio::ssl::context &ctx;
    boost::beast::flat_buffer buffer;
  };
#endif
} // namespace network
