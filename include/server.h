#pragma once

#include "websocket_session.h"
#include "http_session.h"

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

  class detector
  {
  public:
    detector(boost::asio::ip::tcp::socket &&socket, boost::asio::ssl::context &ctx);

    void run();

  private:
    void on_run();
    void on_detect(boost::system::error_code ec, bool result);

    boost::beast::tcp_stream stream;
    boost::asio::ssl::context &ctx;
    boost::beast::flat_buffer buffer;
  };

  /**
   * @brief A server.
   */
  class server
  {
  public:
    server(boost::asio::io_context &ioc, boost::asio::ip::tcp::endpoint endpoint);

    void run();

  private:
    void do_accept();
    void on_accept(boost::system::error_code ec);

    boost::asio::io_context &ioc;
    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::socket socket;
    boost::beast::flat_buffer buffer;
  };
} // namespace network
