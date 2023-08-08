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
      bool keep_alive = msg.keep_alive();
      // Write the response
      boost::beast::http::async_write(this->session.derived().get_stream(), msg, [this, keep_alive](boost::system::error_code ec, size_t bytes_transferred)
                                      { this->on_write(ec, bytes_transferred, keep_alive); });
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
      parser.emplace();

      // we apply a reasonable limit to the allowed size of the body in bytes to prevent abuse..
      parser->body_limit(1024 * 1024);

      // we set a timeout..
      boost::beast::get_lowest_layer(derived().get_stream()).expires_after(std::chrono::seconds(30));

      // we read a request using the parser-oriented interface..
      boost::beast::http::async_read(derived().get_stream(), buffer, *parser, [this](boost::system::error_code ec, size_t bytes_transferred)
                                     { on_read(ec, bytes_transferred); });
    }

    /**
     * @brief Write a response to the client.
     *
     * @return true if the caller should initiate a read operation, false otherwise.
     */
    bool do_write()
    {
      bool const was_full = response_queue.size() == queue_limit;

      if (!response_queue.empty())
      { // we send the response..
        work_ptr<Derived> res = std::move(response_queue.front());
        response_queue.pop();
        res->operator()();
      }

      return was_full;
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

      // the request path must be absolute and not contain "..".
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

      if (response_queue.size() == 1)
        do_write(); // we start the write loop..

      if (response_queue.size() < queue_limit)
        do_read(); // we pipeline another request..
    }
    void on_write(boost::system::error_code ec, size_t, bool keep_alive)
    {
      if (ec)
      {
        LOG_ERR("HTTP write failed: " << ec.message());
        delete this;
        return;
      }

      if (!keep_alive)
      { // this means we should close the connection, usually because the response indicated the "Connection: close" semantic..
        derived().close();
        return;
      }

      // we inform the queue that a write completed..
      if (do_write())
        do_read();
    }

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
