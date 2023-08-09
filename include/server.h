#pragma once

#include "memory.h"
#include "logging.h"
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio.hpp>
#include <queue>
#include <thread>
#include <functional>
#include <regex>

namespace network
{
  class server;

  template <class Derived>
  class websocket_server_session;

  template <class Derived>
  class ws_server_handlers
  {
    friend class websocket_server_session<Derived>;

  public:
    ws_server_handlers &on_open(std::function<void(websocket_server_session<Derived> &)> handler) noexcept
    {
      on_open_handler = handler;
      return *this;
    }
    ws_server_handlers &on_close(std::function<void(websocket_server_session<Derived> &)> handler) noexcept
    {
      on_close_handler = handler;
      return *this;
    }
    ws_server_handlers &on_message(std::function<void(websocket_server_session<Derived> &, const std::string &)> handler) noexcept
    {
      on_message_handler = handler;
      return *this;
    }
    ws_server_handlers &on_error(std::function<void(websocket_server_session<Derived> &, boost::system::error_code)> handler) noexcept
    {
      on_error_handler = handler;
      return *this;
    }

  private:
    std::function<void(websocket_server_session<Derived> &)> on_open_handler = [](websocket_server_session<Derived> &) {};
    std::function<void(websocket_server_session<Derived> &)> on_close_handler = [](websocket_server_session<Derived> &) {};
    std::function<void(websocket_server_session<Derived> &, const std::string &)> on_message_handler = [](websocket_server_session<Derived> &, const std::string &) {};
    std::function<void(websocket_server_session<Derived> &, boost::system::error_code)> on_error_handler = [](websocket_server_session<Derived> &, boost::system::error_code) {};
  };

  template <class Derived>
  class websocket_server_session
  {
    Derived &derived() { return static_cast<Derived &>(*this); }

  public:
    void run(boost::beast::http::request<boost::beast::http::string_body> req)
    {
      // Set suggested timeout settings for the websocket
      derived().get_stream().set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::server));

      // Set a decorator to change the Server of the handshake
      derived().get_stream().set_option(boost::beast::websocket::stream_base::decorator([](boost::beast::websocket::response_type &res)
                                                                                        { res.set(boost::beast::http::field::server, std::string(BOOST_BEAST_VERSION_STRING) + " websocket-server-async"); }));

      // Accept the websocket handshake
      derived().get_stream().async_accept(req, [this](boost::system::error_code ec)
                                          { on_accept(ec); });
    }

  private:
    void on_accept(boost::system::error_code ec)
    {
      if (ec)
      {
        LOG_ERR("websocket accept failed: " << ec.message());
        return;
      }

      // read a message..
      do_read();
    }

    void do_read()
    {
      // read a message into our buffer..
      derived().get_stream().async_read(buffer, [this](boost::system::error_code ec, size_t bytes_transferred)
                                        { on_read(ec, bytes_transferred); });
    }

    void on_read(boost::system::error_code ec, size_t)
    {
      if (ec == boost::beast::websocket::error::closed)
        return; // the websocket session was closed..

      if (ec)
      {
        LOG_ERR("websocket read failed: " << ec.message());
        return;
      }
    }

    void on_write(boost::system::error_code ec, size_t)
    {
      if (ec)
      {
        LOG_ERR("websocket write failed: " << ec.message());
        return;
      }

      // clear the buffer..
      buffer.consume(buffer.size());

      // read another message..
      do_read();
    }

  protected:
    boost::beast::flat_buffer buffer;
  };

  class plain_websocket_server_session : public websocket_server_session<plain_websocket_server_session>
  {
  public:
    plain_websocket_server_session(boost::beast::tcp_stream &&stream) : ws(std::move(stream)) {}

    boost::beast::websocket::stream<boost::beast::tcp_stream> &get_stream() { return ws; }

  private:
    boost::beast::websocket::stream<boost::beast::tcp_stream> ws;
  };

  class ssl_websocket_server_session : public websocket_server_session<ssl_websocket_server_session>
  {
  public:
    ssl_websocket_server_session(boost::beast::ssl_stream<boost::beast::tcp_stream> &&stream) : ws(std::move(stream)) {}

    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>> &get_stream() { return ws; }

  private:
    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>> ws;
  };

  template <class Body, class Allocator>
  void make_websocket_server_session(boost::beast::tcp_stream stream, boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>> req) { (new plain_websocket_server_session(std::move(stream)))->run(std::move(req)); }

  template <class Body, class Allocator>
  void make_websocket_server_session(boost::beast::ssl_stream<boost::beast::tcp_stream> stream, boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>> req) { (new ssl_websocket_server_session(std::move(stream)))->run(std::move(req)); }

  template <class Derived>
  class http_server_session;

  class route
  {
  public:
    route(boost::beast::http::verb method, std::string path) : method(method), path(path) {}
    virtual ~route() {}

    boost::beast::http::verb get_method() const { return method; }
    std::string get_path() const { return path; }

  private:
    boost::beast::http::verb method;
    std::string path;
  };

  using route_ptr = utils::u_ptr<route>;

  template <class ReqBody, class ReqAllocator, class ResBody, class ResAllocator>
  class route_impl : public route
  {
  public:
    route_impl(boost::beast::http::verb method, std::string path, std::function<void(boost::beast::http::request<ReqBody, boost::beast::http::basic_fields<ReqAllocator>> &, boost::beast::http::response<ResBody, boost::beast::http::basic_fields<ResAllocator>> &)> handler) : route(method, path), handler(handler) {}

    void handle(boost::beast::http::request<ReqBody, boost::beast::http::basic_fields<ReqAllocator>> &req, boost::beast::http::response<ResBody, boost::beast::http::basic_fields<ResAllocator>> &res) override { handler(req, res); }

  private:
    std::function<void(const boost::beast::http::request<ReqBody, boost::beast::http::basic_fields<ReqAllocator>> &, boost::beast::http::response<ResBody, boost::beast::http::basic_fields<ResAllocator>> &)> handler;
  };

  template <class Derived>
  struct work
  {
  public:
    work(http_server_session<Derived> &session) : session(session) {}
    virtual ~work() = default;

    virtual void operator()() = 0;

  protected:
    void on_write(boost::system::error_code ec, size_t bytes_transferred, bool close) { session.on_write(ec, bytes_transferred, close); }

  protected:
    http_server_session<Derived> &session;
  };

  template <class Derived>
  using work_ptr = utils::u_ptr<work<Derived>>;

  template <class Derived, class Body, class Fields>
  class server_response : public work<Derived>
  {
  public:
    server_response(http_server_session<Derived> &session, boost::beast::http::message<false, Body, Fields> &&msg) : work<Derived>(session), msg(std::move(msg)) {}

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
  class http_server_session
  {
    friend class work<Derived>;

  public:
    http_server_session(boost::beast::flat_buffer buffer) : buffer(std::move(buffer)) {}

    Derived &derived() { return static_cast<Derived &>(*this); }

    /**
     * @brief Read a request from the client.
     *
     */
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

      // we see if it is a WebSocket Upgrade..
      if (boost::beast::websocket::is_upgrade(parser->get()))
      {
        // we disable the timeout..
        boost::beast::get_lowest_layer(derived().get_stream()).expires_never();

        // we transfer the stream to a new WebSocket session..
        make_websocket_server_session(derived().release_stream(), parser->release());
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
        response_queue.push(new server_response(*this, std::move(res)));
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
  class plain_http_server_session : public http_server_session<plain_http_server_session>
  {
  public:
    plain_http_server_session(boost::beast::tcp_stream &&stream, boost::beast::flat_buffer &&buffer);

    void run();
    void close();

    boost::beast::tcp_stream &get_stream() { return stream; }
    boost::beast::tcp_stream release_stream() { return std::move(stream); }

  private:
    boost::beast::tcp_stream stream;
  };

  /**
   * @brief HTTP session for a WebSocket connection.
   *
   */
  class ssl_http_server_session : public http_server_session<ssl_http_server_session>
  {
  public:
    ssl_http_server_session(boost::beast::tcp_stream &&stream, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&buffer);

    void run();
    void close();

    boost::beast::ssl_stream<boost::beast::tcp_stream> &get_stream() { return stream; }
    boost::beast::ssl_stream<boost::beast::tcp_stream> release_stream() { return std::move(stream); }

  private:
    void on_handshake(boost::system::error_code ec, size_t bytes_used);
    void on_shutdown(boost::system::error_code ec);

  private:
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream;
  };

  /**
   * @brief Detects the session type.
   */
  class session_detector
  {
  public:
    session_detector(boost::asio::ip::tcp::socket &&socket, boost::asio::ssl::context &ctx);

    void run();

  private:
    void on_run();
    void on_detect(boost::system::error_code ec, bool result);

  private:
    boost::beast::flat_buffer buffer;
    boost::beast::tcp_stream stream;
    boost::asio::ssl::context &ctx;
  };

  /**
   * @brief A server.
   */
  class server
  {
  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080, std::size_t thread_pool_size = std::thread::hardware_concurrency());

    /**
     * @brief Run the server.
     */
    void start();

    /**
     * @brief Stop the server.
     */
    void stop();

    void set_ssl_context(const std::string &certificate_chain_file, const std::string &private_key_file);

  private:
    void on_accept(boost::system::error_code ec, boost::asio::ip::tcp::socket socket);

  private:
    std::size_t thread_pool_size;     // The number of threads in the thread pool.
    std::vector<std::thread> threads; // The thread pool.

    boost::asio::io_context ioc;                                      // The io_context is required for all I/O.
    boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12}; // The SSL context is required, and holds certificates.

    boost::asio::signal_set signals;         // The signal_set is used to register for process termination notifications.
    boost::asio::ip::tcp::acceptor acceptor; // The acceptor object used to accept incoming socket connections.
  };
} // namespace network
