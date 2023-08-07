#pragma once

#include "websocket_session.h"

namespace network
{
  /**
   * @brief Return a reasonable mime type based on the extension of a file.
   *
   * @param path The path to the file.
   */
  boost::beast::string_view mime_type(boost::beast::string_view path)
  {
    using boost::beast::iequals;
    auto const ext = [&path]
    {
      auto const pos = path.rfind(".");
      if (pos == boost::beast::string_view::npos)
        return boost::beast::string_view{};
      return path.substr(pos);
    }();
    if (iequals(ext, ".htm"))
      return "text/html";
    if (iequals(ext, ".html"))
      return "text/html";
    if (iequals(ext, ".php"))
      return "text/html";
    if (iequals(ext, ".css"))
      return "text/css";
    if (iequals(ext, ".txt"))
      return "text/plain";
    if (iequals(ext, ".js"))
      return "application/javascript";
    if (iequals(ext, ".json"))
      return "application/json";
    if (iequals(ext, ".xml"))
      return "application/xml";
    if (iequals(ext, ".swf"))
      return "application/x-shockwave-flash";
    if (iequals(ext, ".flv"))
      return "video/x-flv";
    if (iequals(ext, ".png"))
      return "image/png";
    if (iequals(ext, ".jpe"))
      return "image/jpeg";
    if (iequals(ext, ".jpeg"))
      return "image/jpeg";
    if (iequals(ext, ".jpg"))
      return "image/jpeg";
    if (iequals(ext, ".gif"))
      return "image/gif";
    if (iequals(ext, ".bmp"))
      return "image/bmp";
    if (iequals(ext, ".ico"))
      return "image/vnd.microsoft.icon";
    if (iequals(ext, ".tiff"))
      return "image/tiff";
    if (iequals(ext, ".tif"))
      return "image/tiff";
    if (iequals(ext, ".svg"))
      return "image/svg+xml";
    if (iequals(ext, ".svgz"))
      return "image/svg+xml";
    return "application/text";
  }

  /**
   * @brief Append an HTTP rel-path to a local filesystem path.
   *
   * @param base The base path.
   * @param path The path to append.
   */
  std::string path_cat(boost::beast::string_view base, boost::beast::string_view path)
  {
    if (base.empty())
      return std::string(path);
    std::string result(base);
#ifdef BOOST_MSVC
    char constexpr path_separator = '\\';
    if (result.back() == path_separator)
      result.resize(result.size() - 1);
    result.append(path.data(), path.size());
    for (auto &c : result)
      if (c == '/')
        c = path_separator;
#else
    char constexpr path_separator = '/';
    if (result.back() == path_separator)
      result.resize(result.size() - 1);
    result.append(path.data(), path.size());
#endif
    return result;
  }

  struct work
  {
    virtual ~work() = default;
    virtual void run() = 0;
  };

  /**
   * @brief Handles an HTTP server connection.
   *
   * @tparam Body The type of the request body.
   * @tparam Allocator The type of the allocator to use.
   * @tparam Send The type of the send function.
   *
   * @param doc_root The root directory of the server.
   * @param req The request to handle.
   * @param send The send function.
   */
  template <class Body, class Allocator, class Send>
  void handle_request(boost::beast::string_view doc_root, boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>> &&req, Send &&send)
  {
    // A bad request response
    auto const bad_request = [&req](boost::beast::string_view why)
    {
      boost::beast::http::response<boost::beast::http::string_body> res{boost::beast::http::status::bad_request, req.version()};
      res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
      res.set(boost::beast::http::field::content_type, "text/html");
      res.keep_alive(req.keep_alive());
      res.body() = std::string(why);
      res.prepare_payload();
      return res;
    };

    // Returns a not found response
    auto const not_found = [&req](boost::beast::string_view target)
    {
      boost::beast::http::response<boost::beast::http::string_body> res{boost::beast::http::status::not_found, req.version()};
      res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
      res.set(boost::beast::http::field::content_type, "text/html");
      res.keep_alive(req.keep_alive());
      res.body() = "The resource '" + std::string(target) + "' was not found.";
      res.prepare_payload();
      return res;
    };

    // Returns a server error response
    auto const server_error = [&req](boost::beast::string_view what)
    {
      boost::beast::http::response<boost::beast::http::string_body> res{boost::beast::http::status::internal_server_error, req.version()};
      res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
      res.set(boost::beast::http::field::content_type, "text/html");
      res.keep_alive(req.keep_alive());
      res.body() = "An error occurred: '" + std::string(what) + "'";
      res.prepare_payload();
      return res;
    };
  }

  /**
   * @brief Base class for HTTP sessions.
   *
   * @tparam Derived The derived class.
   */
  template <class Derived>
  class http_session
  {
    Derived &derived() { return static_cast<Derived &>(*this); }

    template <bool isRequest, class Body, class Fields>
    class work_impl : public work
    {
    public:
      work_impl(http_session &self, boost::beast::http::message<isRequest, Body, Fields> &&msg) : self(self), msg(std::move(msg)) {}

      void run() override
      {
        boost::beast::http::async_write(self.derived().get_stream(), msg, [self = self.shared_from_this()](boost::system::error_code ec, size_t bytes_transferred)
                                        { self->on_write(ec, bytes_transferred); });
      }

    private:
      http_session &self;
      boost::beast::http::message<isRequest, Body, Fields> msg;
    };

  public:
    http_session(boost::beast::flat_buffer buffer) : buffer(std::move(buffer)) {}

  protected:
    void do_read()
    {
      derived().parser.emplace();
      derived().parser->body_limit(1000000);
      boost::beast::get_lowest_layer(derived().get_stream()).expires_after(std::chrono::seconds(30));
      boost::beast::http::async_read(derived().get_stream(), derived().buffer, *parser, [this](boost::system::error_code ec, size_t bytes_transferred)
                                     { on_read(ec, bytes_transferred); });
    }

  private:
    void on_read(boost::system::error_code ec, [[maybe_unused]] size_t bytes_transferred)
    {
      if (ec == boost::beast::http::error::end_of_stream)
        return derived().do_eof();

      if (ec)
      {
        LOG_ERR("Error: " << ec.message() << "\n");
        delete this;
        return;
      }

      if (boost::beast::websocket::is_upgrade(parser->get()))
      {
        boost::beast::get_lowest_layer(derived().get_stream()).expires_never();

        make_websocket_session(derived().release_stream(), parser->release());
      }

      // Send the response
      handle_request(parser->release(), queue_);
    }

    void on_write(boost::system::error_code ec, [[maybe_unused]] size_t bytes_transferred)
    {
      if (ec)
      {
        LOG_ERR("Error: " << ec.message() << "\n");
        delete this;
        return;
      }

      // Clear the queue
      queue_.clear();

      // Read another request
      do_read();
    }

  private:
    boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser;

  protected:
    boost::beast::flat_buffer buffer;
  };

  /**
   * @brief A plain HTTP session.
   */
  class plain_http_session : public http_session<plain_http_session>
  {
  public:
    plain_http_session(boost::beast::tcp_stream &&stream, boost::beast::flat_buffer &&buffer);

    boost::beast::tcp_stream &get_stream() { return stream; }
    boost::beast::tcp_stream release_stream() { return std::move(stream); }

    void run();

    void do_eof();

  private:
    boost::beast::tcp_stream stream;
  };

  /**
   * @brief An SSL HTTP session.
   */
  class ssl_http_session : public http_session<ssl_http_session>
  {
  public:
    ssl_http_session(boost::beast::tcp_stream &&stream, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&buffer);

    boost::beast::ssl_stream<boost::beast::tcp_stream> &get_stream() { return stream; }
    boost::beast::ssl_stream<boost::beast::tcp_stream> release_stream() { return std::move(stream); }

    void run();

    void do_eof();

  private:
    void on_handshake(boost::system::error_code ec, size_t bytes_transferred);
    void on_shutdown(boost::system::error_code ec);

  private:
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream;
  };
} // namespace network
