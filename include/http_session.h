#pragma once

#include "logging.h"
#include "memory.h"
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <queue>

namespace network
{
  template <class Derived>
  class http_session;

  template <class Derived>
  struct work
  {
  public:
    work(http_session<Derived> &session) : session(session) {}
    virtual ~work() = default;

    virtual void operator()() = 0;

  protected:
    void on_write(boost::system::error_code ec, size_t bytes_transferred, bool close) { session.on_write(ec, bytes_transferred, close); }

  protected:
    http_session<Derived> &session;
  };

  template <class Derived>
  using work_ptr = utils::u_ptr<work<Derived>>;

  template <class Derived, class Body, class Fields>
  class response : public work<Derived>
  {
  public:
    response(http_session<Derived> &session, boost::beast::http::message<false, Body, Fields> &&msg) : work<Derived>(session), msg(std::move(msg)) {}

    void operator()() override
    {
      // Write the response
      boost::beast::http::async_write(this->session.derived().get_stream(), msg, [this](boost::system::error_code ec, size_t bytes_transferred)
                                      { this->on_write(ec, bytes_transferred, msg.need_eof()); });
    }

  private:
    boost::beast::http::message<false, Body> msg;
  };

  /**
   * @brief Base class for HTTP sessions.
   *
   */
  template <class Derived>
  class http_session
  {
    friend class work<Derived>;

  public:
    http_session(boost::beast::flat_buffer buffer) : buffer(std::move(buffer)) {}

    Derived &derived() { return static_cast<Derived &>(*this); }

    void do_read()
    {
      // Make the request empty before reading,
      // otherwise the operation behavior is undefined.
      parser.emplace();

      // Apply a reasonable limit to the allowed size of the body in bytes to prevent abuse.
      parser->body_limit(1024 * 1024);

      // Set the timeout.
      boost::beast::get_lowest_layer(derived().get_stream()).expires_after(std::chrono::seconds(30));

      // Read a request
      boost::beast::http::async_read(derived().get_stream(), buffer, *parser, [this](boost::system::error_code ec, size_t bytes_transferred)
                                     { on_read(ec, bytes_transferred); });
    }

  private:
    void on_read(boost::system::error_code ec, size_t)
    {
      if (ec == boost::beast::http::error::end_of_stream)
      {
        derived().close();
        return;
      }
      else if (ec)
      {
        LOG_ERR("HTTP read failed: " << ec.message());
        delete this;
        return;
      }

      auto req = parser->release();

      // Request path must be absolute and not contain "..".
      if (req.target().empty() || req.target()[0] != '/' || req.target().find("..") != boost::beast::string_view::npos)
      {
        boost::beast::http::response<boost::beast::http::string_body> res{boost::beast::http::status::bad_request, req.version()};
        res.set(boost::beast::http::field::server, "ratioNet server");
        res.set(boost::beast::http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = "Illegal request-target";
        res.prepare_payload();
        response_queue.push(new response(*this, std::move(res)));
      }

      // If we aren't at the queue limit, try to pipeline another request
      if (response_queue.size() < queue_limit)
        do_read();
    }
    void on_write(boost::system::error_code ec, size_t bytes_transferred, bool close) {}

  private:
    static constexpr std::size_t queue_limit = 8; // max responses
    std::queue<work_ptr<Derived>> response_queue;

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
    void close();

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
    void close();

    boost::beast::ssl_stream<boost::beast::tcp_stream> &get_stream() { return stream; }

  private:
    void on_handshake(boost::system::error_code ec, size_t bytes_used);
    void on_shutdown(boost::system::error_code ec);

  private:
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream;
  };
} // namespace network
