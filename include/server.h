#pragma once

#include "logging.h"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <functional>
#include <regex>
#include <thread>
#include <queue>

namespace network
{
  class server;
  template <class Derived>
  class http_session;
  class plain_http_session;
  class ssl_http_session;
  class ws_handler;
  template <class Session>
  class websocket_session;
  class plain_websocket_session;
  class ssl_websocket_session;

  const std::unordered_map<std::string, std::string> mime_types{
      {"shtml", "text/html"},
      {"htm", "text/html"},
      {"html", "text/html"},
      {"css", "text/css"},
      {"xml", "text/xml"},
      {"gif", "image/gif"},
      {"jpg", "image/jpeg"},
      {"jpeg", "image/jpeg"},
      {"js", "application/javascript"},
      {"atom", "application/atom+xml"},
      {"rss", "application/rss+xml"},
      {"mml", "text/mathml"},
      {"txt", "text/plain"},
      {"jad", "text/vnd.sun.j2me.app-descriptor"},
      {"wml", "text/vnd.wap.wml"},
      {"htc", "text/x-component"},
      {"avif", "image/avif"},
      {"png", "image/png"},
      {"svgz", "image/svg+xml"},
      {"svg", "image/svg+xml"},
      {"tiff", "image/tiff"},
      {"tif", "image/tiff"},
      {"wbmp", "image/vnd.wap.wbmp"},
      {"webp", "image/webp"},
      {"ico", "image/x-icon"},
      {"jng", "image/x-jng"},
      {"bmp", "image/x-ms-bmp"},
      {"woff", "font/woff"},
      {"woff2", "font/woff2"},
      {"ear", "application/java-archive"},
      {"war", "application/java-archive"},
      {"jar", "application/java-archive"},
      {"json", "application/json"},
      {"hqx", "application/mac-binhex40"},
      {"doc", "application/msword"},
      {"pdf", "application/pdf"},
      {"ai", "application/postscript"},
      {"eps", "application/postscript"},
      {"ps", "application/postscript"},
      {"rtf", "application/rtf"},
      {"m3u8", "application/vnd.apple.mpegurl"},
      {"kml", "application/vnd.google-earth.kml+xml"},
      {"kmz", "application/vnd.google-earth.kmz"},
      {"xls", "application/vnd.ms-excel"},
      {"eot", "application/vnd.ms-fontobject"},
      {"ppt", "application/vnd.ms-powerpoint"},
      {"odg", "application/vnd.oasis.opendocument.graphics"},
      {"odp", "application/vnd.oasis.opendocument.presentation"},
      {"ods", "application/vnd.oasis.opendocument.spreadsheet"},
      {"odt", "application/vnd.oasis.opendocument.text"},
      {"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
      {"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
      {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
      {"wmlc", "application/vnd.wap.wmlc"},
      {"wasm", "application/wasm"},
      {"7z", "application/x-7z-compressed"},
      {"cco", "application/x-cocoa"},
      {"jardiff", "application/x-java-archive-diff"},
      {"jnlp", "application/x-java-jnlp-file"},
      {"run", "application/x-makeself"},
      {"pm", "application/x-perl"},
      {"pl", "application/x-perl"},
      {"pdb", "application/x-pilot"},
      {"prc", "application/x-pilot"},
      {"rar", "application/x-rar-compressed"},
      {"rpm", "application/x-redhat-package-manager"},
      {"sea", "application/x-sea"},
      {"swf", "application/x-shockwave-flash"},
      {"sit", "application/x-stuffit"},
      {"tk", "application/x-tcl"},
      {"tcl", "application/x-tcl"},
      {"crt", "application/x-x509-ca-cert"},
      {"pem", "application/x-x509-ca-cert"},
      {"der", "application/x-x509-ca-cert"},
      {"xpi", "application/x-xpinstall"},
      {"xhtml", "application/xhtml+xml"},
      {"xspf", "application/xspf+xml"},
      {"zip", "application/zip"},
      {"dll", "application/octet-stream"},
      {"exe", "application/octet-stream"},
      {"bin", "application/octet-stream"},
      {"deb", "application/octet-stream"},
      {"dmg", "application/octet-stream"},
      {"img", "application/octet-stream"},
      {"iso", "application/octet-stream"},
      {"msm", "application/octet-stream"},
      {"msp", "application/octet-stream"},
      {"msi", "application/octet-stream"},
      {"kar", "audio/midi"},
      {"midi", "audio/midi"},
      {"mid", "audio/midi"},
      {"mp3", "audio/mpeg"},
      {"ogg", "audio/ogg"},
      {"m4a", "audio/x-m4a"},
      {"ra", "audio/x-realaudio"},
      {"3gp", "video/3gpp"},
      {"3gpp", "video/3gpp"},
      {"ts", "video/mp2t"},
      {"mp4", "video/mp4"},
      {"mpg", "video/mpeg"},
      {"mpeg", "video/mpeg"},
      {"mov", "video/quicktime"},
      {"webm", "video/webm"},
      {"flv", "video/x-flv"},
      {"m4v", "video/x-m4v"},
      {"mng", "video/x-mng"},
      {"asf", "video/x-ms-asf"},
      {"asx", "video/x-ms-asf"},
      {"wmv", "video/x-ms-wmv"},
      {"avi", "video/x-msvideo"}};

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
  void make_websocket_session(server &srv, boost::beast::tcp_stream stream, boost::beast::http::request<Body> req, ws_handler &handler) { std::make_shared<plain_websocket_session>(srv, std::move(stream), std::move(req), handler); }

  template <class Body>
  void make_websocket_session(server &srv, boost::beast::ssl_stream<boost::beast::tcp_stream> stream, boost::beast::http::request<Body> req, ws_handler &handler) { std::make_shared<ssl_websocket_session>(srv, std::move(stream), std::move(req), handler); }

  boost::optional<http_handler &> get_http_handler(server &srv, boost::beast::http::verb method, const std::string &target, bool ssl);
  boost::optional<ws_handler &> get_ws_handler(server &srv, const std::string &target, bool ssl);

  template <class Derived>
  class http_session : public std::enable_shared_from_this<Derived>
  {
    Derived &derived() { return static_cast<Derived &>(*this); }

  public:
    http_session(server &srv, boost::beast::flat_buffer &&buffer) : srv(srv), buffer(std::move(buffer)) {}
    virtual ~http_session() = default;

    virtual bool is_ssl() const = 0;

    template <class Body>
    void enqueue(boost::beast::http::response<Body> &&res)
    {
      response_queue.push(std::make_unique<server_response_impl<Derived, Body>>(derived(), std::move(res)));

      if (response_queue.size() > 1)
        return; // already sending

      response_queue.front()->do_write();
    }

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
        auto handler = get_ws_handler(srv, req.target().to_string(), is_ssl());
        if (handler)
          make_websocket_session(srv, derived().release_stream(), std::move(req), handler.get());
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
      if (auto handler = get_http_handler(srv, req.method(), target, is_ssl()); handler)
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
    plain_http_session(server &srv, boost::beast::tcp_stream &&str, boost::beast::flat_buffer &&buffer) : http_session(srv, std::move(buffer)), stream(std::move(str)) { do_read(); }

    bool is_ssl() const override { return false; }

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

  class ssl_http_session : public http_session<ssl_http_session>
  {
    friend class http_session<ssl_http_session>;

  public:
    ssl_http_session(server &srv, boost::beast::tcp_stream &&str, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&bfr) : http_session(srv, std::move(bfr)), stream(std::move(str), ctx)
    {
      boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));                                                                                            // Set the timeout
      stream.async_handshake(boost::asio::ssl::stream_base::server, buffer.data(), boost::beast::bind_front_handler(&ssl_http_session::on_handshake, this->shared_from_this())); // Perform the SSL handshake
    }

    bool is_ssl() const override { return true; }

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

  class ws_handler
  {
  public:
    virtual ~ws_handler() = default;
  };

  template <class Session>
  class ws_handler_impl : public ws_handler
  {
    friend class websocket_session<Session>;

  public:
    ws_handler_impl<Session> &on_open(const std::function<void(Session &)> &handler) noexcept
    {
      on_open_handler = handler;
      return *this;
    }
    ws_handler_impl<Session> &on_close(const std::function<void(Session &)> &handler) noexcept
    {
      on_close_handler = handler;
      return *this;
    }
    ws_handler_impl<Session> &on_message(const std::function<void(Session &, const std::string &)> &handler) noexcept
    {
      on_message_handler = handler;
      return *this;
    }
    ws_handler_impl<Session> &on_error(const std::function<void(Session &, boost::beast::error_code)> &handler) noexcept
    {
      on_error_handler = handler;
      return *this;
    }

  private:
    std::function<void(Session &)> on_open_handler = [](Session &) {};
    std::function<void(Session &)> on_close_handler = [](Session &) {};
    std::function<void(Session &, const std::string &)> on_message_handler = [](Session &, const std::string &) {};
    std::function<void(Session &, boost::beast::error_code)> on_error_handler = [](Session &, boost::beast::error_code) {};
  };

  template <class Derived>
  class websocket_session : public std::enable_shared_from_this<Derived>
  {
    Derived &derived() { return static_cast<Derived &>(*this); }

  public:
    websocket_session(server &srv, ws_handler &handler) : srv(srv), handler(handler) {}
    virtual ~websocket_session() = default;

    void send(const std::string &&msg) { send(std::make_shared<std::string>(msg)); }

    void send(const std::shared_ptr<const std::string> &msg) { enqueue(msg); }

    void close(boost::beast::websocket::close_code code = boost::beast::websocket::close_code::normal) { derived().get_websocket().async_close(code, boost::beast::bind_front_handler(&websocket_session::on_close, this->shared_from_this())); }

  protected:
    template <class Body>
    void do_accept(boost::beast::http::request<Body> req)
    {
      derived().get_websocket().set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::server));
      derived().get_websocket().set_option(boost::beast::websocket::stream_base::decorator([](boost::beast::websocket::response_type &res)
                                                                                           { res.set(boost::beast::http::field::server, "ratioNet"); }));
      derived().get_websocket().async_accept(req, boost::beast::bind_front_handler(&websocket_session::on_accept, this->shared_from_this()));
    }

  private:
    void on_accept(boost::beast::error_code ec)
    {
      if (ec)
        return static_cast<ws_handler_impl<Derived> &>(handler).on_error_handler(derived(), ec);

      static_cast<ws_handler_impl<Derived> &>(handler).on_open_handler(derived());

      do_read();
    }

    void do_read() { derived().get_websocket().async_read(buffer, boost::beast::bind_front_handler(&websocket_session::on_read, this->shared_from_this())); }
    void on_read(boost::beast::error_code ec, std::size_t)
    {
      if (ec == boost::beast::websocket::error::closed) // This indicates that the session was closed
        return static_cast<ws_handler_impl<Derived> &>(handler).on_close_handler(derived());
      else if (ec)
        return static_cast<ws_handler_impl<Derived> &>(handler).on_error_handler(derived(), ec);

      static_cast<ws_handler_impl<Derived> &>(handler).on_message_handler(derived(), boost::beast::buffers_to_string(buffer.data()));

      buffer.consume(buffer.size()); // Clear the buffer

      do_read(); // Read another message
    }

    void enqueue(const std::shared_ptr<const std::string> &msg)
    {
      if (!derived().get_websocket().get_executor().running_in_this_thread())
        return boost::asio::post(derived().get_websocket().get_executor(), boost::beast::bind_front_handler(&websocket_session::enqueue, this->shared_from_this(), msg));

      send_queue.push(msg);

      if (send_queue.size() > 1)
        return; // already sending

      do_write();
    }

    void do_write() { derived().get_websocket().async_write(boost::asio::buffer(*send_queue.front()), boost::asio::bind_executor(derived().get_websocket().get_executor(), boost::beast::bind_front_handler(&websocket_session::on_write, this->shared_from_this()))); }
    void on_write(boost::beast::error_code ec, std::size_t)
    {
      if (ec)
        return static_cast<ws_handler_impl<Derived> &>(handler).on_error_handler(derived(), ec);

      send_queue.pop();

      if (!send_queue.empty())
        do_write();
    }

    void on_close(boost::beast::error_code ec)
    {
      if (ec)
        return static_cast<ws_handler_impl<Derived> &>(handler).on_error_handler(derived(), ec);

      static_cast<ws_handler_impl<Derived> &>(handler).on_close_handler(derived());
    }

  private:
    server &srv;
    boost::beast::flat_buffer buffer;
    std::queue<std::shared_ptr<const std::string>> send_queue;
    ws_handler &handler;
  };

  class plain_websocket_session : public websocket_session<plain_websocket_session>
  {
    friend class websocket_session<plain_websocket_session>;

  public:
    template <class Body>
    plain_websocket_session(server &srv, boost::beast::tcp_stream &&stream, boost::beast::http::request<Body> req, ws_handler &handler) : websocket_session(srv, handler), websocket(std::move(stream)) { do_accept(std::move(req)); }
    ~plain_websocket_session() {}

  private:
    boost::beast::websocket::stream<boost::beast::tcp_stream> &get_websocket() { return websocket; }

  private:
    boost::beast::websocket::stream<boost::beast::tcp_stream> websocket;
  };

  class ssl_websocket_session : public websocket_session<ssl_websocket_session>
  {
    friend class websocket_session<ssl_websocket_session>;

  public:
    template <class Body>
    ssl_websocket_session(server &srv, boost::beast::ssl_stream<boost::beast::tcp_stream> &&stream, boost::beast::http::request<Body> req, ws_handler &handler) : websocket_session(srv, handler), websocket(std::move(stream)) { do_accept(std::move(req)); }
    ~ssl_websocket_session() {}

  private:
    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>> &get_websocket() { return websocket; }

  private:
    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>> websocket;
  };

  class session_detector : public std::enable_shared_from_this<session_detector>
  {
  public:
    session_detector(server &srv, boost::asio::ip::tcp::socket &&socket, boost::asio::ssl::context &ctx) : srv(srv), stream(std::move(socket)), ctx(ctx) { boost::asio::dispatch(stream.get_executor(), boost::beast::bind_front_handler(&session_detector::on_run, shared_from_this())); }

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
        std::make_shared<ssl_http_session>(srv, std::move(stream), ctx, std::move(buffer));
      else
        std::make_shared<plain_http_session>(srv, std::move(stream), std::move(buffer));
    }

  private:
    server &srv;
    boost::beast::tcp_stream stream;
    boost::asio::ssl::context &ctx;
    boost::beast::flat_buffer buffer;
  };

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
    void add_route(boost::beast::http::verb method, const std::string &path, const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> &handler, bool ssl = false) noexcept
    {
      if (ssl)
        https_routes[method].push_back(std::make_pair(std::regex(path), std::make_unique<http_handler_impl<ssl_http_session, ReqBody, ResBody>>(handler)));
      else
        http_routes[method].push_back(std::make_pair(std::regex(path), std::make_unique<http_handler_impl<plain_http_session, ReqBody, ResBody>>(handler)));
    }

    ws_handler &add_ws_route(const std::string &path, bool ssl = false) noexcept
    {
      if (ssl)
      {
        wss_routes.push_back(std::make_pair(std::regex(path), std::make_unique<ws_handler_impl<ssl_websocket_session>>()));
        return *wss_routes.back().second;
      }
      else
      {
        ws_routes.push_back(std::make_pair(std::regex(path), std::make_unique<ws_handler_impl<plain_websocket_session>>()));
        return *ws_routes.back().second;
      }
    }

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

      for (auto i = threads.size(); i > 0; --i)
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

    void set_ssl_context(const std::string &certificate_file, const std::string &private_key_file, const std::string &dh_file)
    {
      ctx.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::single_dh_use);

      ctx.use_certificate_file(certificate_file, boost::asio::ssl::context::pem);
      ctx.use_private_key_file(private_key_file, boost::asio::ssl::context::pem);
      ctx.use_tmp_dh_file(dh_file);
    }

  private:
    void do_accept()
    {
      acceptor.async_accept(boost::asio::make_strand(io_ctx), [this](boost::beast::error_code ec, boost::asio::ip::tcp::socket socket)
                            { on_accept(ec, std::move(socket)); });
    }

    void on_accept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket)
    {
      if (ec)
      {
        LOG_ERR(ec.message());
      }
      else
      {
        LOG_DEBUG("Accepted connection from " << socket.remote_endpoint());
        new session_detector(*this, std::move(socket), ctx);
      }

      do_accept();
    }

    friend boost::optional<http_handler &> get_http_handler(server &srv, boost::beast::http::verb method, const std::string &target, bool ssl);
    friend boost::optional<ws_handler &> get_ws_handler(server &srv, const std::string &target, bool ssl);

  private:
    boost::asio::io_context io_ctx;                                        // The io_context is required for all I/O
    std::vector<std::thread> threads;                                      // The thread pool
    boost::asio::signal_set signals;                                       // The signal_set is used to register for process termination notifications
    boost::asio::ip::tcp::endpoint endpoint;                               // The endpoint for the server
    boost::asio::ssl::context ctx{boost::asio::ssl::context::TLS_VERSION}; // The SSL context is required, and holds certificates
    boost::asio::ip::tcp::acceptor acceptor;                               // The acceptor receives incoming connections
    std::unordered_map<boost::beast::http::verb, std::vector<std::pair<std::regex, std::unique_ptr<http_handler>>>> http_routes, https_routes;
    std::vector<std::pair<std::regex, std::unique_ptr<ws_handler>>> ws_routes, wss_routes;
  };

  inline boost::optional<http_handler &> get_http_handler(server &srv, boost::beast::http::verb method, const std::string &target, bool ssl = false)
  {
    for (auto &handler : ssl ? srv.https_routes[method] : srv.http_routes[method])
      if (std::regex_match(target, handler.first))
        return *handler.second;
    return boost::none;
  }

  inline boost::optional<ws_handler &> get_ws_handler(server &srv, const std::string &target, bool ssl = false)
  {
    for (auto &handler : ssl ? srv.wss_routes : srv.ws_routes)
      if (std::regex_match(target, handler.first))
        return *handler.second;
    return boost::none;
  }

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
