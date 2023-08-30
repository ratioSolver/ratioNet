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

  class request;
  using request_ptr = utils::u_ptr<request>;
  class response;
  using response_ptr = utils::u_ptr<response>;

  class ws_handler
  {
  public:
    virtual ~ws_handler() = default;
  };
  using ws_handler_ptr = utils::u_ptr<ws_handler>;

  template <class Session>
  class ws_handler_impl : public ws_handler
  {

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
    ws_handler_impl<Session> &on_error(std::function<void(Session &, boost::system::error_code)> handler) noexcept
    {
      on_error_handler = handler;
      return *this;
    }

  private:
    std::function<void(Session &)> on_open_handler = [](Session &) {};
    std::function<void(Session &)> on_close_handler = [](Session &) {};
    std::function<void(Session &, const std::string &)> on_message_handler = [](Session &, const std::string &) {};
    std::function<void(Session &, boost::system::error_code)> on_error_handler = [](Session &, boost::system::error_code) {};
  };

  /**
   * @brief The server class.
   */
  class server
  {
    friend class request_handler;
    friend class ssl_request_handler;
    friend class http_session;
    friend class websocket_session;
    friend class ssl_http_session;
    friend class ssl_websocket_session;

  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080, std::size_t concurrency_hint = std::thread::hardware_concurrency());

    void add_route(boost::beast::http::verb method, const std::string &path, std::function<response_ptr(request &)> handler) noexcept { http_routes[method].push_back(std::make_pair(std::regex(path), handler)); }

    ws_handler &add_ws_route(const std::string &path) noexcept
    {
      ws_routes.push_back(std::make_pair(std::regex(path), new ws_handler_impl<websocket_session>()));
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
    std::unordered_map<boost::beast::http::verb, std::vector<std::pair<std::regex, std::function<response_ptr(request &)>>>> http_routes;
    std::vector<std::pair<std::regex, ws_handler_ptr>> ws_routes;
  };
} // namespace network
