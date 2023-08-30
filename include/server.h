#pragma once

#include "http_session.h"
#include "ssl_http_session.h"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <functional>
#include <regex>
#include <thread>

namespace network
{
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

  template <class Session>
  class request_handler
  {
    friend class http_session;
    friend class ssl_http_session;

  public:
    request_handler(Session &session) : session(session) {}
    virtual ~request_handler() = default;

  private:
    virtual void handle_request() = 0;

  protected:
    template <class Body, class Fields>
    void handle_req(boost::beast::http::request<Body, Fields> &&req)
    {
      if (req.target().empty() || req.target().size() > 1024 || req.target()[0] != '/' || req.target().find("..") != boost::beast::string_view::npos)
      {
        boost::beast::http::response<boost::beast::http::string_body> res{boost::beast::http::status::bad_request, req.version()};
        res.set(boost::beast::http::field::server, "ratioNet");
        res.set(boost::beast::http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        if (req.target().empty())
          res.body() = "Empty request target";
        else if (req.target().size() > 1024)
          res.body() = "Request target too long";
        else if (req.target()[0] != '/')
          res.body() = "Request target must begin with '/'";
        else if (req.target().find("..") != boost::beast::string_view::npos)
          res.body() = "Request target must not contain '..'";
        else
          res.body() = "Bad request";
        res.prepare_payload();
        boost::beast::http::async_write(session.stream, res, [this](boost::beast::error_code ec, std::size_t bytes_transferred)
                                        { session.on_write(ec, bytes_transferred, true); });
        return;
      }
    }

  private:
    Session &session;
  };

  template <class Session, class Body, class Fields>
  class request_handler_impl : public request_handler<Session>
  {
  public:
    request_handler_impl(Session &session, boost::beast::http::request<Body, Fields> &&req) : request_handler<Session>(session), req(std::move(req)) {}
    virtual ~request_handler_impl() = default;

  private:
    void handle_request() override { request_handler<Session>::handle_req(std::move(req)); }

  private:
    boost::beast::http::request<Body, Fields> req;
  };

  /**
   * @brief The server class.
   */
  class server
  {
    friend class request_handler<http_session>;
    friend class request_handler<ssl_http_session>;
    friend class http_session;
    friend class websocket_session;
    friend class ssl_http_session;
    friend class ssl_websocket_session;

  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080, std::size_t concurrency_hint = std::thread::hardware_concurrency());

    /**
     * @brief Start the server.
     */
    void start();
    /**
     * @brief Stop the server.
     */
    void stop();

    void set_ssl_context(const std::string &certificate_chain_file, const std::string &private_key_file, const std::string &dh_file);

  private:
    void on_accept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket);

  private:
    boost::asio::io_context ioc;                                      // The io_context is required for all I/O
    std::vector<std::thread> threads;                                 // The thread pool
    boost::asio::signal_set signals;                                  // The signal_set is used to register for process termination notifications
    boost::asio::ip::tcp::endpoint endpoint;                          // The endpoint for the server
    boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12}; // The SSL context is required, and holds certificates
    boost::asio::ip::tcp::acceptor acceptor;                          // The acceptor receives incoming connections
    std::vector<std::pair<std::regex, ws_handler>> ws_routes;
    std::vector<std::pair<std::regex, ssl_ws_handler>> ssl_ws_routes;
  };
} // namespace network
