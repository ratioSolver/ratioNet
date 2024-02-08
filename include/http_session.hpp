#pragma once

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#ifdef USE_SSL
#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>
#endif

namespace network
{
  class base_server;
  class http_handler;
  class websocket_handler;

  class base_http_session
  {
  public:
    base_http_session(base_server &srv, boost::beast::flat_buffer &&buffer) : srv(srv), buffer(std::move(buffer)) {}

    virtual void run() = 0;
    virtual void do_eof() = 0;

  protected:
    boost::optional<http_handler &> get_http_handler(boost::beast::http::verb method, const std::string &target);
    boost::optional<websocket_handler &> get_ws_handler(const std::string &target);
#ifdef USE_SSL
    boost::optional<http_handler &> get_https_handler(boost::beast::http::verb method, const std::string &target);
    boost::optional<websocket_handler &> get_wss_handler(const std::string &target);
#endif

    template <class Body>
    boost::optional<boost::beast::http::response<boost::beast::http::string_body>> check_request(const boost::beast::http::request<Body> &req)
    {
      if (req.target().empty() || req.target()[0] != '/' || req.target().find("..") != boost::beast::string_view::npos)
      {
        boost::beast::http::response<boost::beast::http::string_body> res(boost::beast::http::status::bad_request, req.version());
        res.set(boost::beast::http::field::server, "ratioNet");
        res.set(boost::beast::http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        if (req.target().empty())
          res.body() = "The path must not be empty";
        else if (req.target()[0] != '/')
          res.body() = "The path must begin with '/'";
        else if (req.target().find("..") != boost::beast::string_view::npos)
          res.body() = "The path must not contain '..'";
        else
          res.body() = "Bad request";
        return res;
      }
      else
        return boost::none;
    }

    template <class Body>
    boost::beast::http::response<boost::beast::http::string_body> no_handler(const boost::beast::http::request<Body> &req)
    {
      boost::beast::http::response<boost::beast::http::string_body> res(boost::beast::http::status::not_found, req.version());
      res.set(boost::beast::http::field::server, "ratioNet");
      res.set(boost::beast::http::field::content_type, "text/html");
      res.keep_alive(req.keep_alive());
      res.body() = "The resource '" + std::string(req.target()) + "' was not found";
      return res;
    }

  protected:
    void fire_on_error(const boost::beast::error_code &ec);

  protected:
    base_server &srv;
    boost::beast::flat_buffer buffer;
    boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser;
  };

  class http_session : public base_http_session
  {
  public:
    http_session(base_server &srv, boost::beast::tcp_stream &&str, boost::beast::flat_buffer &&buffer) : base_http_session(srv, std::move(buffer)), stream(std::move(str)) {}

  protected:
    boost::beast::tcp_stream stream;
  };

#ifdef USE_SSL
  class session_detector
  {
  public:
    session_detector(base_server &srv, boost::asio::ip::tcp::socket &&socket, boost::asio::ssl::context &ssl_ctx) : srv(srv), stream(std::move(socket)), ssl_ctx(ssl_ctx) {}

    virtual void run() = 0;

  protected:
    void fire_on_error(const boost::beast::error_code &ec);

  protected:
    base_server &srv;
    boost::beast::tcp_stream stream;
    boost::asio::ssl::context &ssl_ctx;
    boost::beast::flat_buffer buffer;
  };

  class ssl_session : public base_http_session
  {
  public:
    ssl_session(base_server &srv, boost::beast::tcp_stream &&str, boost::asio::ssl::context &ssl_ctx, boost::beast::flat_buffer &&buffer) : base_http_session(srv, std::move(buffer)), stream(std::move(str), ssl_ctx) {}

  protected:
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream;
  };
#endif
} // namespace network
