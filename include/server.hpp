#pragma once

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>
#ifdef USE_SSL
#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>
#endif
#include <boost/beast/websocket.hpp>
#include <functional>
#include <regex>
#include <thread>
#include <queue>
#include "mime_types.hpp"

#ifdef VERBOSE_LOG
#include <iostream>

#ifdef WIN32
#define COLOR_NORMAL ""
#define COLOR_RED ""
#define COLOR_GREEN ""
#define COLOR_YELLOW ""
#else
#define COLOR_NORMAL "\033[0m"
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#endif

#define LOG_ERR(msg) std::cerr << COLOR_RED << __FILE__ << "(" << __LINE__ << "): " << msg << COLOR_NORMAL << std::endl
#define LOG_WARN(msg) std::clog << COLOR_YELLOW << __FILE__ << "(" << __LINE__ << "): " << msg << COLOR_NORMAL << std::endl
#define LOG_DEBUG(msg) std::clog << COLOR_GREEN << __FILE__ << "(" << __LINE__ << "): " << msg << COLOR_NORMAL << std::endl
#define LOG(msg) std::cout << COLOR_NORMAL << __FILE__ << "(" << __LINE__ << "): " << msg << COLOR_NORMAL << std::endl
#else
#define LOG_ERR(msg) \
  {                  \
  }
#define LOG_WARN(msg) \
  {                   \
  }
#define LOG_DEBUG(msg) \
  {                    \
  }
#define LOG(msg) \
  {              \
  }
#endif

#define GET(server, target, handler) server.add_route(boost::beast::http::verb::get, target, std::function{handler})
#define POST(server, target, handler) server.add_route(boost::beast::http::verb::post, target, std::function{handler})
#define PUT(server, target, handler) server.add_route(boost::beast::http::verb::put, target, std::function{handler})
#define DELETE(server, target, handler) server.add_route(boost::beast::http::verb::delete_, target, std::function{handler})

namespace network
{
  class server;
  template <class Derived>
  class http_session;
  class plain_http_session;
  class ssl_http_session;
  template <class Session>
  class websocket_session_impl;
  class plain_websocket_session;
  class ssl_websocket_session;

  class websocket_session
  {
  public:
    virtual ~websocket_session() = default;

    /**
     * @brief Send a message to the client.
     *
     * @param msg The message to send.
     */
    virtual void send(const std::string &&msg) = 0;
    /**
     * @brief Send a message to the client.
     *
     * @param msg The message to send.
     */
    virtual void send(const std::shared_ptr<const std::string> &msg) = 0;
    /**
     * @brief Close the connection.
     *
     * @param code The close code.
     */
    virtual void close(boost::beast::websocket::close_code code = boost::beast::websocket::close_code::normal) = 0;
  };

  class ws_handler
  {
    friend class websocket_session_impl<plain_websocket_session>;
    friend class websocket_session_impl<ssl_websocket_session>;

  public:
    /**
     * @brief Called when the connection is opened.
     *
     * @param handler The handler to call.
     */
    ws_handler &on_open(const std::function<void(websocket_session &)> &handler) noexcept
    {
      on_open_handler = handler;
      return *this;
    }
    ws_handler &on_close(const std::function<void(websocket_session &, const boost::beast::websocket::close_reason)> &handler) noexcept
    {
      on_close_handler = handler;
      return *this;
    }
    ws_handler &on_message(const std::function<void(websocket_session &, const std::string &)> &handler) noexcept
    {
      on_message_handler = handler;
      return *this;
    }
    ws_handler &on_error(const std::function<void(websocket_session &, boost::beast::error_code)> &handler) noexcept
    {
      on_error_handler = handler;
      return *this;
    }

  private:
    std::function<void(websocket_session &)> on_open_handler = [](websocket_session &) {};
    std::function<void(websocket_session &, const boost::beast::websocket::close_reason)> on_close_handler = [](websocket_session &, const boost::beast::websocket::close_reason) {};
    std::function<void(websocket_session &, const std::string &)> on_message_handler = [](websocket_session &, const std::string &) {};
    std::function<void(websocket_session &, boost::beast::error_code)> on_error_handler = [](websocket_session &, boost::beast::error_code) {};
  };

  template <class Derived>
  class websocket_session_impl : public websocket_session, public std::enable_shared_from_this<Derived>
  {
    Derived &derived() { return static_cast<Derived &>(*this); }

  public:
    websocket_session_impl(server &srv, ws_handler &handler) : srv(srv), handler(handler) {}
    virtual ~websocket_session_impl() = default;

    void send(const std::string &&msg) { send(std::make_shared<std::string>(msg)); }

    void send(const std::shared_ptr<const std::string> &msg) { boost::asio::post(derived().get_websocket().get_executor(), boost::beast::bind_front_handler(&websocket_session_impl::enqueue, this->shared_from_this(), msg)); }

    void close(boost::beast::websocket::close_code code = boost::beast::websocket::close_code::normal) { derived().get_websocket().async_close(code, boost::beast::bind_front_handler(&websocket_session_impl::on_close, this->shared_from_this())); }

    template <class Body>
    void do_accept(boost::beast::http::request<Body> req)
    {
      derived().get_websocket().set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::server));
      derived().get_websocket().set_option(boost::beast::websocket::stream_base::decorator([](boost::beast::websocket::response_type &res)
                                                                                           { res.set(boost::beast::http::field::server, "ratioNet"); }));
      derived().get_websocket().async_accept(req, boost::beast::bind_front_handler(&websocket_session_impl::on_accept, this->shared_from_this()));
    }

  private:
    void on_accept(boost::beast::error_code ec)
    {
      if (ec)
        return handler.on_error_handler(derived(), ec);

      handler.on_open_handler(derived());

      do_read();
    }

    void do_read() { derived().get_websocket().async_read(buffer, boost::beast::bind_front_handler(&websocket_session_impl::on_read, this->shared_from_this())); }
    void on_read(boost::beast::error_code ec, std::size_t)
    {
      if (ec == boost::beast::websocket::error::closed) // This indicates that the session was closed
        return handler.on_close_handler(derived(), derived().get_websocket().reason());
      else if (ec)
        return handler.on_error_handler(derived(), ec);

      handler.on_message_handler(derived(), boost::beast::buffers_to_string(buffer.data()));

      buffer.consume(buffer.size()); // Clear the buffer

      do_read(); // Read another message
    }

    void enqueue(const std::shared_ptr<const std::string> &msg)
    {
      send_queue.push(msg);

      if (send_queue.size() > 1)
        return; // already sending

      do_write();
    }

    void do_write() { derived().get_websocket().async_write(boost::asio::buffer(*send_queue.front()), boost::asio::bind_executor(derived().get_websocket().get_executor(), boost::beast::bind_front_handler(&websocket_session_impl::on_write, this->shared_from_this()))); }
    void on_write(boost::beast::error_code ec, std::size_t)
    {
      if (ec)
        return handler.on_error_handler(derived(), ec);

      send_queue.pop();

      if (!send_queue.empty())
        do_write();
    }

    void on_close(boost::beast::error_code ec)
    {
      if (ec)
        return handler.on_error_handler(derived(), ec);

      handler.on_close_handler(derived(), derived().get_websocket().reason());
    }

  private:
    server &srv;
    boost::beast::flat_buffer buffer;
    std::queue<std::shared_ptr<const std::string>> send_queue;
    ws_handler &handler;
  };

  class plain_websocket_session : public websocket_session_impl<plain_websocket_session>
  {
    friend class websocket_session_impl<plain_websocket_session>;

  public:
    plain_websocket_session(server &srv, boost::beast::tcp_stream &&stream, ws_handler &handler) : websocket_session_impl(srv, handler), websocket(std::move(stream)) {}
    ~plain_websocket_session() {}

  private:
    boost::beast::websocket::stream<boost::beast::tcp_stream> &get_websocket() { return websocket; }

  private:
    boost::beast::websocket::stream<boost::beast::tcp_stream> websocket;
  };

#ifdef USE_SSL
  class ssl_websocket_session : public websocket_session_impl<ssl_websocket_session>
  {
    friend class websocket_session_impl<ssl_websocket_session>;

  public:
    ssl_websocket_session(server &srv, boost::beast::ssl_stream<boost::beast::tcp_stream> &&stream, ws_handler &handler) : websocket_session_impl(srv, handler), websocket(std::move(stream)) {}
    ~ssl_websocket_session() {}

  private:
    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>> &get_websocket() { return websocket; }

  private:
    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>> websocket;
  };
#endif

  class server_request
  {
  public:
    virtual ~server_request() = default;
  };

  template <class Session, class Body>
  class server_request_impl : public server_request
  {
  public:
    server_request_impl(Session &session, boost::beast::http::request<Body> &&req) : session(session), req(std::move(req)) {}

  public:
    Session &session;
    boost::beast::http::request<Body> req;
  };

  class server_response
  {
  public:
    virtual ~server_response() = default;

    virtual void do_write() = 0;
  };

  template <class Session, class Body>
  class server_response_impl : public server_response
  {
  public:
    server_response_impl(Session &session, boost::beast::http::response<Body> &&res) : session(session), res(std::move(res)) {}

    void do_write() override { session.do_write(res); }

  public:
    Session &session;
    boost::beast::http::response<Body> res;
  };

  class http_handler
  {
    friend class http_session<plain_http_session>;
    friend class http_session<ssl_http_session>;

  public:
    virtual ~http_handler() = default;

  private:
    virtual void handle_request(const server_request &&req) = 0;

  protected:
    template <class Session, class ReqBody, class ResBody>
    void handle_request(Session &session, const boost::beast::http::request<ReqBody> &req, const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> &handler)
    {
      boost::beast::http::response<ResBody> res(boost::beast::http::status::ok, req.version());
      res.set(boost::beast::http::field::server, "ratioNet");
      res.set(boost::beast::http::field::content_type, "text/html");
      res.keep_alive(req.keep_alive());
      try
      {
        handler(req, res);
        res.prepare_payload();
        session.enqueue(std::move(res));
      }
      catch (const std::exception &e)
      {
        LOG_WARN(e.what());
        boost::beast::http::response<boost::beast::http::string_body> c_res(boost::beast::http::status::bad_request, req.version());
        c_res.set(boost::beast::http::field::server, "ratioNet");
        c_res.set(boost::beast::http::field::content_type, "text/html");
        c_res.keep_alive(req.keep_alive());
        c_res.body() = e.what();
        c_res.prepare_payload();
        session.enqueue(std::move(c_res));
      }
    }
  };

  template <class Session, class ReqBody, class ResBody>
  class http_handler_impl : public http_handler
  {
  public:
    http_handler_impl(const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> &handler) : handler(handler) {}

  private:
    void handle_request(const server_request &&req) override { http_handler::handle_request(static_cast<const server_request_impl<Session, ReqBody> &>(req).session, static_cast<const server_request_impl<Session, ReqBody> &>(req).req, handler); }

  private:
    const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> handler;
  };

  template <class Body>
  void make_websocket_session(server &srv, boost::beast::tcp_stream stream, boost::beast::http::request<Body> req, ws_handler &handler) { std::make_shared<plain_websocket_session>(srv, std::move(stream), handler)->do_accept(std::move(req)); }

#ifdef USE_SSL
  template <class Body>
  void make_websocket_session(server &srv, boost::beast::ssl_stream<boost::beast::tcp_stream> stream, boost::beast::http::request<Body> req, ws_handler &handler) { std::make_shared<ssl_websocket_session>(srv, std::move(stream), handler)->do_accept(std::move(req)); }
#endif

  boost::optional<http_handler &> get_http_handler(server &srv, boost::beast::http::verb method, const std::string &target);
  boost::optional<ws_handler &> get_ws_handler(server &srv, const std::string &target);

#ifdef USE_SSL
  boost::optional<http_handler &> get_https_handler(server &srv, boost::beast::http::verb method, const std::string &target);
  boost::optional<ws_handler &> get_wss_handler(server &srv, const std::string &target);
#endif

  template <class Derived>
  class http_session : public std::enable_shared_from_this<Derived>
  {
    Derived &derived() { return static_cast<Derived &>(*this); }

  public:
    http_session(server &srv, boost::beast::flat_buffer &&buffer) : srv(srv), buffer(std::move(buffer)) {}
    virtual ~http_session() = default;

#ifdef USE_SSL
    virtual bool is_ssl() const = 0;
#endif

    template <class Body>
    void enqueue(boost::beast::http::response<Body> &&res) { boost::asio::post(derived().get_stream().get_executor(), boost::beast::bind_front_handler(&http_session::enqueue_response<Body>, this->shared_from_this(), std::move(res))); }

    template <class Body>
    void do_write(boost::beast::http::response<Body> &res) { boost::beast::http::async_write(derived().get_stream(), res, boost::beast::bind_front_handler(&http_session::on_write, this->shared_from_this(), res.keep_alive())); }

  protected:
    void do_read()
    {
      parser.emplace();                                                                               // Construct a new parser for each message
      parser->body_limit(10000);                                                                      // Set the limit on the allowed size of a message
      boost::beast::get_lowest_layer(derived().get_stream()).expires_after(std::chrono::seconds(30)); // Set the timeout

      boost::beast::http::async_read(derived().get_stream(), buffer, *parser, boost::beast::bind_front_handler(&http_session::on_read, this->shared_from_this())); // Read a request
    }

  private:
    template <class Body>
    void enqueue_response(boost::beast::http::response<Body> &&res)
    {
      response_queue.push(std::make_unique<server_response_impl<Derived, Body>>(derived(), std::move(res)));

      if (response_queue.size() > 1)
        return; // already sending

      response_queue.front()->do_write();
    }

    void on_read(boost::beast::error_code ec, std::size_t)
    {
      if (ec == boost::beast::http::error::end_of_stream)
        return do_eof();

      if (ec)
      {
        LOG_ERR(ec.message());
        return;
      }

      if (boost::beast::websocket::is_upgrade(parser->get()))
      {                                                                         // If this is a WebSocket upgrade request, transfer control to a WebSocket session
        boost::beast::get_lowest_layer(derived().get_stream()).expires_never(); // Turn off the timeout on the tcp_stream, because the websocket stream has its own timeout system.
        auto req = parser->release();
#ifdef USE_SSL
        auto handler = is_ssl() ? get_wss_handler(srv, req.target().to_string()) : get_ws_handler(srv, req.target().to_string());
#else
        auto handler = get_ws_handler(srv, req.target().to_string());
#endif
        if (handler)
          make_websocket_session(srv, derived().release_stream(), std::move(req), handler.get());
        else
        {
          LOG_WARN("No handler found for WebSocket " << req.target());
        }
        return;
      }

      handle_request(parser->release()); // Handle the HTTP request
    }

    template <class Body>
    void handle_request(boost::beast::http::request<Body> &&req)
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
        res.prepare_payload();
        enqueue(std::move(res));
        return;
      }

      std::string target = req.target().to_string();
#ifdef USE_SSL
      auto handler = is_ssl() ? get_https_handler(srv, req.method(), target) : get_http_handler(srv, req.method(), target);
#else
      auto handler = get_http_handler(srv, req.method(), target);
#endif
      if (handler)
        return handler.get().handle_request(server_request_impl<Derived, Body>(derived(), std::move(req)));
      else
      {
        LOG_WARN("No handler found for " << req.method() << " " << target);
        boost::beast::http::response<boost::beast::http::string_body> res(boost::beast::http::status::bad_request, req.version());
        res.set(boost::beast::http::field::server, "ratioNet");
        res.set(boost::beast::http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = "Bad request";
        res.prepare_payload();
        enqueue(std::move(res));
      }
    }

    void on_write(bool keep_alive, boost::beast::error_code ec, std::size_t)
    {
      if (ec)
      {
        LOG_ERR(ec.message());
        return;
      }

      if (!keep_alive) // This means we should close the connection, usually because the response indicated the "Connection: close" semantic.
        return do_eof();

      response_queue.pop();

      do_read();
    }

    virtual void do_eof() = 0;

  protected:
    server &srv;
    boost::beast::flat_buffer buffer;

  private:
    boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser; // The parser for reading the request. The parser is stored in an optional container so we can construct it from scratch it at the beginning of each new message.
    std::queue<std::unique_ptr<server_response>> response_queue;
  };

  class plain_http_session : public http_session<plain_http_session>
  {
    friend class http_session<plain_http_session>;

  public:
    plain_http_session(server &srv, boost::beast::tcp_stream &&str, boost::beast::flat_buffer &&buffer) : http_session(srv, std::move(buffer)), stream(std::move(str)) {}

#ifdef USE_SSL
    bool is_ssl() const override { return false; }
#endif

    void run() { do_read(); }

  private:
    boost::beast::tcp_stream &get_stream() { return stream; }
    boost::beast::tcp_stream release_stream() { return std::move(stream); }

    void do_eof() override
    {
      boost::beast::error_code ec;
      stream.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    }

  private:
    boost::beast::tcp_stream stream;
  };

#ifdef USE_SSL
  class ssl_http_session : public http_session<ssl_http_session>
  {
    friend class http_session<ssl_http_session>;

  public:
    ssl_http_session(server &srv, boost::beast::tcp_stream &&str, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&bfr) : http_session(srv, std::move(bfr)), stream(std::move(str), ctx) {}

    bool is_ssl() const override { return true; }

    void run()
    {
      boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));                                                                                            // Set the timeout
      stream.async_handshake(boost::asio::ssl::stream_base::server, buffer.data(), boost::beast::bind_front_handler(&ssl_http_session::on_handshake, this->shared_from_this())); // Perform the SSL handshake
    }

  private:
    boost::beast::ssl_stream<boost::beast::tcp_stream> &get_stream() { return stream; }
    boost::beast::ssl_stream<boost::beast::tcp_stream> release_stream() { return std::move(stream); }

    void on_handshake(boost::beast::error_code ec, std::size_t bytes_used)
    {
      if (ec)
      {
        LOG_ERR(ec.message());
      }
      else
      {
        buffer.consume(bytes_used); // Consume the portion of the buffer used by the handshake
        do_read();                  // Start reading a new request
      }
    }

    void do_eof() override
    {
      boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));                                    // Set the timeout
      stream.async_shutdown(boost::beast::bind_front_handler(&ssl_http_session::on_shutdown, this->shared_from_this())); // Perform the SSL shutdown
    }
    void on_shutdown(boost::beast::error_code ec)
    {
      if (ec)
      {
        LOG_ERR(ec.message());
      }
    }

  private:
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream;
  };

  class session_detector : public std::enable_shared_from_this<session_detector>
  {
  public:
    session_detector(server &srv, boost::asio::ip::tcp::socket &&socket, boost::asio::ssl::context &ctx) : srv(srv), stream(std::move(socket)), ctx(ctx) {}

    void run() { boost::asio::dispatch(stream.get_executor(), boost::beast::bind_front_handler(&session_detector::on_run, shared_from_this())); }

  private:
    void on_run()
    {
      stream.expires_after(std::chrono::seconds(30));                                                                                     // Set the timeout
      boost::beast::async_detect_ssl(stream, buffer, boost::beast::bind_front_handler(&session_detector::on_detect, shared_from_this())); // Detect SSL
    }

    void on_detect(boost::beast::error_code ec, bool result)
    {
      if (ec)
      {
        LOG_ERR(ec.message());
      }
      else if (result)
        std::make_shared<ssl_http_session>(srv, std::move(stream), ctx, std::move(buffer))->run();
      else
        std::make_shared<plain_http_session>(srv, std::move(stream), std::move(buffer))->run();
    }

  private:
    server &srv;
    boost::beast::tcp_stream stream;
    boost::asio::ssl::context &ctx;
    boost::beast::flat_buffer buffer;
  };
#endif

  /**
   * @brief The server class.
   */
  class server
  {
  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080, std::size_t concurrency_hint = std::thread::hardware_concurrency()) : io_ctx(concurrency_hint), signals(io_ctx), endpoint(boost::asio::ip::make_address(address), port), acceptor(boost::asio::make_strand(io_ctx))
    {
      signals.add(SIGINT);
      signals.add(SIGTERM);
#if defined(SIGQUIT)
      signals.add(SIGQUIT);
#endif // defined(SIGQUIT)

      signals.async_wait([this](boost::beast::error_code ec, [[maybe_unused]] int signo)
                         {
                            LOG_DEBUG("Received signal " << signo);
                            if (ec)
                            {
                              LOG_ERR("signals: " << ec.message());
                              return;
                            }
                            
                            stop(); });

      threads.reserve(concurrency_hint);
    }

    template <class ReqBody, class ResBody>
    void add_route(boost::beast::http::verb method, const std::string &path, const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> &handler) noexcept { http_routes[method].push_back(std::make_pair(std::regex(path), std::make_unique<http_handler_impl<plain_http_session, ReqBody, ResBody>>(handler))); }
    ws_handler &ws(const std::string &path) noexcept { return *ws_routes.emplace_back(std::regex(path), std::make_unique<ws_handler>()).second; }

#ifdef USE_SSL
    template <class ReqBody, class ResBody>
    void add_ssl_route(boost::beast::http::verb method, const std::string &path, const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> &handler) noexcept { https_routes[method].push_back(std::make_pair(std::regex(path), std::make_unique<http_handler_impl<ssl_http_session, ReqBody, ResBody>>(handler))); }
    ws_handler &wss(const std::string &path) noexcept { return *wss_routes.emplace_back(std::regex(path), std::make_unique<ws_handler>()).second; }
#endif

    /**
     * @brief Start the server.
     */
    void start()
    {
      LOG("Starting server on " << endpoint);

      boost::beast::error_code ec;
      acceptor.open(endpoint.protocol(), ec);
      if (ec)
      {
        LOG_ERR(ec.message());
        return;
      }

      acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec);
      if (ec)
      {
        LOG_ERR(ec.message());
        return;
      }

      acceptor.bind(endpoint, ec);
      if (ec)
      {
        LOG_ERR(ec.message());
        return;
      }

      acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
      if (ec)
      {
        LOG_ERR(ec.message());
        return;
      }

      do_accept();

      for (auto i = threads.capacity(); i > 0; --i)
        threads.emplace_back([this]
                             { io_ctx.run(); });

      io_ctx.run();
    }
    /**
     * @brief Stop the server.
     */
    void stop()
    {
      LOG("Stopping server");
      io_ctx.stop();
      for (auto &thread : threads)
        thread.join();
    }

#ifdef USE_SSL
    /**
     * @brief Set the ssl context.
     *
     * @param certificate_file The certificate file.
     * @param private_key_file The private key file.
     * @param dh_file The dh file.
     */
    void set_ssl_context(const std::string &certificate_file, const std::string &private_key_file, const std::string &dh_file)
    {
      ctx.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::single_dh_use);

      ctx.use_certificate_file(certificate_file, boost::asio::ssl::context::pem);
      ctx.use_private_key_file(private_key_file, boost::asio::ssl::context::pem);
      ctx.use_tmp_dh_file(dh_file);
    }
#endif

  private:
    void do_accept() { acceptor.async_accept(boost::asio::make_strand(io_ctx), boost::beast::bind_front_handler(&server::on_accept, this)); }

    void on_accept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket)
    {
      if (ec)
      {
        LOG_ERR(ec.message());
      }
      else
      {
        LOG_DEBUG("Accepted connection from " << socket.remote_endpoint());
#ifdef USE_SSL
        std::make_shared<session_detector>(*this, std::move(socket), ctx)->run();
#else
        std::make_shared<plain_http_session>(*this, boost::beast::tcp_stream(std::move(socket)), boost::beast::flat_buffer())->run();
#endif
      }

      do_accept();
    }

    friend boost::optional<http_handler &> get_http_handler(server &srv, boost::beast::http::verb method, const std::string &target);
    friend boost::optional<ws_handler &> get_ws_handler(server &srv, const std::string &target);

#ifdef USE_SSL
    friend boost::optional<http_handler &> get_https_handler(server &srv, boost::beast::http::verb method, const std::string &target);
    friend boost::optional<ws_handler &> get_wss_handler(server &srv, const std::string &target);
#endif

  private:
    boost::asio::io_context io_ctx;          // The io_context is required for all I/O
    std::vector<std::thread> threads;        // The thread pool
    boost::asio::signal_set signals;         // The signal_set is used to register for process termination notifications
    boost::asio::ip::tcp::endpoint endpoint; // The endpoint for the server
    boost::asio::ip::tcp::acceptor acceptor; // The acceptor receives incoming connections
    std::unordered_map<boost::beast::http::verb, std::vector<std::pair<std::regex, std::unique_ptr<http_handler>>>> http_routes;
    std::vector<std::pair<std::regex, std::unique_ptr<ws_handler>>> ws_routes;
#ifdef USE_SSL
    boost::asio::ssl::context ctx{boost::asio::ssl::context::TLS_VERSION}; // The SSL context is required, and holds certificates
    std::unordered_map<boost::beast::http::verb, std::vector<std::pair<std::regex, std::unique_ptr<http_handler>>>> https_routes;
    std::vector<std::pair<std::regex, std::unique_ptr<ws_handler>>> wss_routes;
#endif
  };

  /**
   * @brief Get the http handler object.
   *
   * Returns the http handler for the given method and target.
   *
   * @param srv The server.
   * @param method The http method.
   * @param target The target.
   * @param ssl Whether the connection is ssl or not.
   */
  inline boost::optional<http_handler &> get_http_handler(server &srv, boost::beast::http::verb method, const std::string &target)
  {
    for (auto &handler : srv.http_routes[method])
      if (std::regex_match(target, handler.first))
        return *handler.second;
    return boost::none;
  }

  /**
   * @brief Get the websocket handler object.
   *
   * Returns the websocket handler for the given target.
   *
   * @param srv The server.
   * @param target The target.
   * @param ssl Whether the connection is ssl or not.
   */
  inline boost::optional<ws_handler &> get_ws_handler(server &srv, const std::string &target)
  {
    for (auto &handler : srv.ws_routes)
      if (std::regex_match(target, handler.first))
        return *handler.second;
    return boost::none;
  }

#ifdef USE_SSL
  /**
   * @brief Get the http handler object.
   *
   * Returns the http handler for the given method and target.
   *
   * @param srv The server.
   * @param method The http method.
   * @param target The target.
   * @param ssl Whether the connection is ssl or not.
   */
  inline boost::optional<http_handler &> get_https_handler(server &srv, boost::beast::http::verb method, const std::string &target)
  {
    for (auto &handler : srv.https_routes[method])
      if (std::regex_match(target, handler.first))
        return *handler.second;
    return boost::none;
  }

  /**
   * @brief Get the websocket handler object.
   *
   * Returns the websocket handler for the given target.
   *
   * @param srv The server.
   * @param target The target.
   * @param ssl Whether the connection is ssl or not.
   */
  inline boost::optional<ws_handler &> get_wss_handler(server &srv, const std::string &target)
  {
    for (auto &handler : srv.wss_routes)
      if (std::regex_match(target, handler.first))
        return *handler.second;
    return boost::none;
  }
#endif

  inline std::map<std::string, std::string> parse_query(const std::string &query)
  {
    std::map<std::string, std::string> params;

    std::string::size_type pos = 0;
    while (pos < query.size())
    {
      std::string::size_type next = query.find('&', pos);
      std::string::size_type eq = query.find('=', pos);
      if (eq == std::string::npos)
        break;
      if (next == std::string::npos)
        next = query.size();
      params.emplace(query.substr(pos, eq - pos), query.substr(eq + 1, next - eq - 1));
      pos = next + 1;
    }

    return params;
  }
} // namespace network