#pragma once

#include "memory.h"
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
  template <class Session>
  class request_handler;
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

  class request
  {
  public:
    virtual ~request() = default;

    virtual boost::string_view get_target() const noexcept = 0;
    virtual boost::beast::http::verb get_method() const noexcept = 0;
    virtual unsigned get_version() const noexcept = 0;
    virtual bool keep_alive() const noexcept = 0;
  };
  using request_ptr = utils::u_ptr<request>;

  template <class Session, class Body, class Fields>
  class request_impl : public request
  {
  public:
    request_impl(Session &session, boost::beast::http::request<Body, Fields> &&req) : session(session), req(std::move(req)) {}

    boost::string_view get_target() const noexcept { return req.target(); }
    boost::beast::http::verb get_method() const noexcept { return req.method(); }
    unsigned get_version() const noexcept { return req.version(); }
    bool keep_alive() const noexcept { return req.keep_alive(); }

    Session &get_session() const noexcept { return session; }

  private:
    Session &session;
    boost::beast::http::request<Body, Fields> req;
  };

  class response
  {
    friend class request_handler<plain_http_session>;
    friend class request_handler<ssl_http_session>;

  public:
    virtual ~response() = default;

  private:
    virtual void handle_response() = 0;
  };
  using response_ptr = utils::u_ptr<response>;

  template <class Session, class Body, class Fields>
  void handle_res(Session &session, boost::beast::http::response<Body, Fields> &&res)
  {
    bool close = res.need_eof();
    boost::beast::http::async_write(session.get_stream(), res, [&session, close](boost::beast::error_code ec, std::size_t bytes_transferred)
                                    { session.on_write(ec, bytes_transferred, close); });
  }

  template <class Session, class Body, class Fields>
  class response_impl : public response
  {
  public:
    response_impl(Session &session, boost::beast::http::response<Body, Fields> &&res) : session(session), res(std::move(res)) {}
    virtual ~response_impl() = default;

  private:
    void handle_response() override
    {
      res.set(boost::beast::http::field::server, "ratioNet");
      res.prepare_payload();
      handle_res(session, std::move(res));
    }

  private:
    Session &session;
    boost::beast::http::response<Body, Fields> res;
  };

  template <class Session>
  class request_handler
  {
  public:
    request_handler(Session &session, request_ptr &&req) : session(session), req(std::move(req)) {}

    void handle_request()
    {
      if (req->get_target().empty() || req->get_target()[0] != '/' || req->get_target().find("..") != boost::beast::string_view::npos)
      {
        auto res = new boost::beast::http::response<boost::beast::http::string_body>(boost::beast::http::status::bad_request, req->get_version());
        res->set(boost::beast::http::field::server, "ratioNet");
        res->set(boost::beast::http::field::content_type, "text/html");
        res->keep_alive(req->keep_alive());
        if (req->get_target().empty())
          res->body() = "The path must not be empty";
        else if (req->get_target()[0] != '/')
          res->body() = "The path must begin with '/'";
        else if (req->get_target().find("..") != boost::beast::string_view::npos)
          res->body() = "The path must not contain '..'";
        else
          res->body() = "Bad request";
        res->prepare_payload();
        boost::beast::http::async_write(session.get_stream(), *res, [this, res](boost::beast::error_code ec, std::size_t bytes_transferred)
                                        { session.on_write(ec, bytes_transferred, res->need_eof()); delete res; });
        return;
      }

      std::string target = req->get_target().to_string();
      for (auto &handler : session.srv.http_routes[req->get_method()])
        if (std::regex_match(target, handler.first))
          return handler.second(*req)->handle_response();

      LOG_WARN("No handler found for " << req->get_method() << " " << target);
      auto res = new boost::beast::http::response<boost::beast::http::string_body>(boost::beast::http::status::bad_request, req->get_version());
      res->set(boost::beast::http::field::server, "ratioNet");
      res->set(boost::beast::http::field::content_type, "text/html");
      res->keep_alive(req->keep_alive());
      res->body() = "Bad request";
      res->prepare_payload();
      boost::beast::http::async_write(session.get_stream(), *res, [this, res](boost::beast::error_code ec, std::size_t bytes_transferred)
                                      { session.on_write(ec, bytes_transferred, res->need_eof()); delete res; });
    }

  private:
    Session &session;
    request_ptr req;
  };

  template <class Body, class Allocator>
  void make_websocket_session(server &srv, boost::beast::tcp_stream stream, boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>> req, ws_handler &handler) { new plain_websocket_session(srv, std::move(stream), std::move(req), handler); }

  template <class Body, class Allocator>
  void make_websocket_session(server &srv, boost::beast::ssl_stream<boost::beast::tcp_stream> stream, boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>> req, ws_handler &handler) { new ssl_websocket_session(srv, std::move(stream), std::move(req), handler); }

  boost::optional<ws_handler &> get_ws_handler(server &srv, const std::string &target);

  template <class Derived>
  class http_session
  {
    friend class request_handler<plain_http_session>;
    friend class request_handler<ssl_http_session>;

    Derived &derived() { return static_cast<Derived &>(*this); }

  public:
    http_session(server &srv, boost::beast::flat_buffer &&buffer, size_t queue_limit = 8) : srv(srv), buffer(std::move(buffer)), queue_limit(queue_limit) {}
    virtual ~http_session() = default;

  protected:
    void do_read()
    {
      parser.emplace();                                                                               // Construct a new parser for each message
      parser->body_limit(10000);                                                                      // Set the limit on the allowed size of a message
      boost::beast::get_lowest_layer(derived().get_stream()).expires_after(std::chrono::seconds(30)); // Set the timeout

      boost::beast::http::async_read(derived().get_stream(), buffer, *parser, [this](boost::beast::error_code ec, std::size_t bytes_transferred)
                                     { on_read(ec, bytes_transferred); }); // Read a request
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
        auto handler = get_ws_handler(srv, req.target().to_string());
        if (handler)
          make_websocket_session(srv, derived().release_stream(), std::move(req), handler.get());
        delete this; // Delete this session
        return;
      }

      work_queue.emplace(new request_handler(derived(), new request_impl(derived(), parser->release()))); // Send the request to the queue
      if (work_queue.size() == 1)                                                                         // If this is the first request in the queue, we need to start the work
        work_queue.back()->handle_request();
      if (work_queue.size() < queue_limit) // If we aren't at the queue limit, try to pipeline another request
        do_read();
    }
    void on_write(boost::beast::error_code ec, std::size_t, bool close)
    {
      if (ec)
      {
        LOG_ERR(ec.message());
        return;
      }

      if (close) // This means we should close the connection, usually because the response indicated the "Connection: close" semantic.
        return do_eof();

      work_queue.pop();                    // Remove the current request from the queue
      if (work_queue.size() < queue_limit) // If we aren't at the queue limit, try to pipeline another request
        do_read();
    }

    virtual void do_eof() = 0;

    template <class Session, class Body, class Fields>
    friend void handle_res(Session &session, boost::beast::http::response<Body, Fields> &&res);

  protected:
    server &srv;
    boost::beast::flat_buffer buffer;

  private:
    boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser;
    const size_t queue_limit;                                      // The limit on the allowed size of the queue
    std::queue<utils::u_ptr<request_handler<Derived>>> work_queue; // This queue is used for the work that is to be done on the session
  };

  class plain_http_session : public http_session<plain_http_session>
  {
    friend class http_session<plain_http_session>;
    friend class request_handler<plain_http_session>;

  public:
    plain_http_session(server &srv, boost::beast::tcp_stream &&str, boost::beast::flat_buffer &&buffer, size_t queue_limit = 8) : http_session(srv, std::move(buffer), queue_limit), stream(std::move(str)) { do_read(); }

  private:
    boost::beast::tcp_stream &get_stream() { return stream; }
    boost::beast::tcp_stream release_stream() { return std::move(stream); }

    template <class Session, class Body, class Fields>
    friend void handle_res(Session &session, boost::beast::http::response<Body, Fields> &&res);

    void do_eof() override
    {
      boost::beast::error_code ec;
      stream.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
      delete this; // Delete this session
    }

  private:
    boost::beast::tcp_stream stream;
  };

  class ssl_http_session : public http_session<ssl_http_session>
  {
    friend class http_session<ssl_http_session>;
    friend class request_handler<ssl_http_session>;

  public:
    ssl_http_session(server &srv, boost::beast::tcp_stream &&str, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&buffer, size_t queue_limit = 8) : http_session(srv, std::move(buffer), queue_limit), stream(std::move(str), ctx)
    {
      boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30)); // Set the timeout
      stream.async_handshake(boost::asio::ssl::stream_base::server, buffer.data(), [this](boost::beast::error_code ec, std::size_t)
                             { on_handshake(ec); }); // Perform the SSL handshake
    }

  private:
    boost::beast::ssl_stream<boost::beast::tcp_stream> &get_stream() { return stream; }
    boost::beast::ssl_stream<boost::beast::tcp_stream> release_stream() { return std::move(stream); }

    template <class Session, class Body, class Fields>
    friend void handle_res(Session &session, boost::beast::http::response<Body, Fields> &&res);

    void on_handshake(boost::beast::error_code ec)
    {
      if (ec)
      {
        LOG_ERR(ec.message());
        delete this;
      }
      else
      {
        buffer.consume(buffer.size()); // Consume the portion of the buffer used by the handshake

        do_read();
      }
    }

    void do_eof() override
    {
      boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30)); // Set the timeout
      stream.async_shutdown([this](boost::beast::error_code ec)
                            { on_shutdown(ec); }); // Perform the SSL shutdown
    }
    void on_shutdown(boost::beast::error_code ec)
    {
      if (ec)
      {
        LOG_ERR(ec.message());
      }
      else
      {
        LOG_DEBUG("SSL shutdown");
      }
      delete this; // Delete this session
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
    ws_handler_impl<Session> &on_open(std::function<void(Session &)> handler) noexcept
    {
      on_open_handler = handler;
      return *this;
    }
    ws_handler_impl<Session> &on_close(std::function<void(Session &)> handler) noexcept
    {
      on_close_handler = handler;
      return *this;
    }
    ws_handler_impl<Session> &on_message(std::function<void(Session &, const std::string &)> handler) noexcept
    {
      on_message_handler = handler;
      return *this;
    }
    ws_handler_impl<Session> &on_error(std::function<void(Session &, boost::beast::error_code)> handler) noexcept
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
  class websocket_session
  {
    Derived &derived() { return static_cast<Derived &>(*this); }

  public:
    template <class Body, class Allocator>
    websocket_session(server &srv, boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>> req, ws_handler &handler) : srv(srv), handler(handler)
    {
      derived().get_websocket().set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::server));
      derived().get_websocket().set_option(boost::beast::websocket::stream_base::decorator([](boost::beast::websocket::response_type &res)
                                                                                           { res.set(boost::beast::http::field::server, "ratioNet"); }));
      derived().get_websocket().async_accept(req, [this](boost::beast::error_code ec)
                                             { on_accept(ec); });
    }
    virtual ~websocket_session() = default;

    void send(const std::string &msg)
    {
      // post to strand to avoid concurrent write..
      boost::asio::post(derived().get_websocket().get_executor(), [this, msg]()
                        { derived().get_websocket().async_write(boost::asio::buffer(msg), [this](boost::beast::error_code ec, std::size_t bytes_transferred)
                                                                { on_write(ec, bytes_transferred); }); });
    }

    void close(boost::beast::websocket::close_code code = boost::beast::websocket::close_code::normal)
    {
      derived().get_websocket().async_close(code, [this](boost::beast::error_code ec)
                                            { on_close(ec); });
    }

  private:
    void on_accept(boost::beast::error_code ec)
    {
      if (ec)
      {
        LOG_ERR(ec.message());
        static_cast<ws_handler_impl<Derived> &>(handler).on_error_handler(derived(), ec);
        delete this;
      }

      static_cast<ws_handler_impl<Derived> &>(handler).on_open_handler(derived());

      do_read();
    }

    void do_read()
    {
      derived().get_websocket().async_read(buffer, [this](boost::beast::error_code ec, std::size_t bytes_transferred)
                                           { on_read(ec, bytes_transferred); });
    }
    void on_read(boost::beast::error_code ec, std::size_t)
    {
      if (ec == boost::beast::websocket::error::closed)
      { // This indicates that the session was closed
        delete this;
        return;
      }
      else if (ec)
      {
        LOG_ERR(ec.message());
        static_cast<ws_handler_impl<Derived> &>(handler).on_error_handler(derived(), ec);
        delete this;
        return;
      }

      static_cast<ws_handler_impl<Derived> &>(handler).on_message_handler(derived(), boost::beast::buffers_to_string(buffer.data()));
    }

    void on_write(boost::beast::error_code ec, std::size_t)
    {
      if (ec)
      {
        LOG_ERR(ec.message());
        static_cast<ws_handler_impl<Derived> &>(handler).on_error_handler(derived(), ec);
        delete this;
        return;
      }

      buffer.consume(buffer.size()); // Clear the buffer

      do_read(); // Read another message
    }

    void on_close(boost::beast::error_code ec)
    {
      if (ec)
      {
        LOG_ERR(ec.message());
        static_cast<ws_handler_impl<Derived> &>(handler).on_error_handler(derived(), ec);
      }

      static_cast<ws_handler_impl<Derived> &>(handler).on_close_handler(derived());
      delete this;
    }

  private:
    server &srv;
    boost::beast::flat_buffer buffer;
    ws_handler &handler;
  };

  class plain_websocket_session : public websocket_session<plain_websocket_session>
  {
    friend class websocket_session<plain_websocket_session>;

  public:
    template <class Body, class Allocator>
    plain_websocket_session(server &srv, boost::beast::tcp_stream &&stream, boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>> req, ws_handler &handler) : websocket_session(srv, std::move(req), handler), websocket(std::move(stream)) {}
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
    template <class Body, class Allocator>
    ssl_websocket_session(server &srv, boost::beast::ssl_stream<boost::beast::tcp_stream> &&stream, boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>> req, ws_handler &handler) : websocket_session(srv, std::move(req), handler), websocket(std::move(stream)) {}
    ~ssl_websocket_session() {}

  private:
    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>> &get_websocket() { return websocket; }

  private:
    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>> websocket;
  };

  class session_detector
  {
  public:
    session_detector(server &srv, boost::asio::ip::tcp::socket &&socket, boost::asio::ssl::context &ctx) : srv(srv), stream(std::move(socket)), ctx(ctx)
    {
      boost::asio::dispatch(stream.get_executor(), [this]
                            { boost::beast::async_detect_ssl(stream, buffer, [this](boost::beast::error_code ec, bool result)
                                                             { on_detect(ec, result); }); });
    }

  private:
    void on_detect(boost::beast::error_code ec, bool result)
    {
      if (ec)
      {
        LOG_ERR(ec.message());
      }
      else if (result)
      {
        LOG_DEBUG("SSL connection detected");
        new ssl_http_session(srv, std::move(stream), ctx, std::move(buffer));
      }
      else
      {
        LOG_DEBUG("Plain HTTP connection detected");
        new plain_http_session(srv, std::move(stream), std::move(buffer));
      }
      delete this;
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
    friend class request_handler<plain_http_session>;
    friend class request_handler<ssl_http_session>;
    friend class http_session<plain_http_session>;
    friend class http_session<ssl_http_session>;
    friend class websocket_session<plain_websocket_session>;
    friend class websocket_session<ssl_websocket_session>;

  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080, std::size_t concurrency_hint = std::thread::hardware_concurrency()) : io_ctx(concurrency_hint), signals(io_ctx), endpoint(boost::asio::ip::make_address(address), port), acceptor(boost::asio::make_strand(io_ctx))
    {
      signals.add(SIGINT);
      signals.add(SIGTERM);
#if defined(SIGQUIT)
      signals.add(SIGQUIT);
#endif // defined(SIGQUIT)

      signals.async_wait([this](boost::beast::error_code /*ec*/, int /*signo*/)
                         { stop(); });

      threads.reserve(concurrency_hint);
    }

    void add_route(boost::beast::http::verb method, const std::string &path, std::function<response_ptr(request &)> handler) noexcept { http_routes[method].push_back(std::make_pair(std::regex(path), handler)); }

    ws_handler &add_ws_route(const std::string &path) noexcept
    {
      ws_routes.push_back(std::make_pair(std::regex(path), new ws_handler_impl<plain_websocket_session>()));
      return *ws_routes.back().second;
    }

    ws_handler &add_ssl_ws_route(const std::string &path) noexcept
    {
      ws_routes.push_back(std::make_pair(std::regex(path), new ws_handler_impl<ssl_websocket_session>()));
      return *ws_routes.back().second;
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

      acceptor.async_accept(boost::asio::make_strand(io_ctx), [this](boost::beast::error_code ec, boost::asio::ip::tcp::socket socket)
                            { on_accept(ec, std::move(socket)); });

      for (auto i = threads.size(); i > 0; --i)
        threads.emplace_back([this]
                             { io_ctx.run(); });

      io_ctx.run();
    }
    /**
     * @brief Stop the server.
     */
    void stop() { io_ctx.stop(); }

    void set_ssl_context(const std::string &certificate_chain_file, const std::string &private_key_file, const std::string &dh_file)
    {
      ctx.use_certificate_chain_file(certificate_chain_file);
      ctx.use_private_key_file(private_key_file, boost::asio::ssl::context::pem);
      ctx.use_tmp_dh_file(dh_file);
    }

  private:
    void on_accept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket)
    {
      if (ec)
      {
        LOG_ERR(ec.message());
      }
      else
      {
        LOG_DEBUG("Accepted connection from " << socket.remote_endpoint());
        boost::asio::dispatch(acceptor.get_executor(), [this, socket = std::move(socket)]() mutable
                              { new session_detector(*this, std::move(socket), ctx); });
      }

      acceptor.async_accept(boost::asio::make_strand(io_ctx), [this](boost::beast::error_code ec, boost::asio::ip::tcp::socket socket)
                            { on_accept(ec, std::move(socket)); });
    }

    template <class Session, class Body, class Fields>
    friend void handle_res(Session &session, boost::beast::http::response<Body, Fields> &&res);

    friend boost::optional<ws_handler &> get_ws_handler(server &srv, const std::string &target);

  private:
    boost::asio::io_context io_ctx;                                   // The io_context is required for all I/O
    std::vector<std::thread> threads;                                 // The thread pool
    boost::asio::signal_set signals;                                  // The signal_set is used to register for process termination notifications
    boost::asio::ip::tcp::endpoint endpoint;                          // The endpoint for the server
    boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12}; // The SSL context is required, and holds certificates
    boost::asio::ip::tcp::acceptor acceptor;                          // The acceptor receives incoming connections
    std::unordered_map<boost::beast::http::verb, std::vector<std::pair<std::regex, std::function<response_ptr(request &)>>>> http_routes;
    std::vector<std::pair<std::regex, utils::u_ptr<ws_handler>>> ws_routes;
  };

  boost::optional<ws_handler &> get_ws_handler(server &srv, const std::string &target)
  {
    for (auto &handler : srv.ws_routes)
      if (std::regex_match(target, handler.first))
        return *handler.second;
    return boost::none;
  }
} // namespace network
