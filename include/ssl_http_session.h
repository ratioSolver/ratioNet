#pragma once

#include "memory.h"
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <queue>
#include <functional>

namespace network
{
  class server;
  template <class Session>
  class request_handler;

  class ssl_http_session
  {
    friend class request_handler<ssl_http_session>;

  public:
    ssl_http_session(server &srv, boost::beast::tcp_stream &&stream, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&buffer, size_t queue_limit = 8);

  private:
    void on_handshake(boost::beast::error_code ec); // Perform the SSL handshake
    void do_read();                                 // Start reading a request

    void on_read(boost::beast::error_code ec, std::size_t bytes_transferred);
    void on_write(boost::beast::error_code ec, std::size_t bytes_transferred, bool close);

    void do_eof();
    void on_shutdown(boost::beast::error_code ec);

  private:
    server &srv;
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream;
    boost::beast::flat_buffer buffer;
    boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser;
    const size_t queue_limit;                                               // The limit on the allowed size of the queue
    std::queue<utils::u_ptr<request_handler<ssl_http_session>>> work_queue; // This queue is used for the work that is to be done on the session
  };

  class ssl_ws_handler;

  class ssl_websocket_session
  {
  public:
    template <class Body, class Allocator>
    ssl_websocket_session(server &srv, boost::beast::ssl_stream<boost::beast::tcp_stream> &&stream, boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>> req) : srv(srv), ws(std::move(stream)), handler(get_ssl_ws_handler(req.target().to_string()))
    {
      ws.set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::server));
      ws.set_option(boost::beast::websocket::stream_base::decorator([](boost::beast::websocket::response_type &res)
                                                                    { res.set(boost::beast::http::field::server, "ratioNet"); }));
      ws.async_accept(req, [this](boost::beast::error_code ec)
                      { on_accept(ec); });

      if (!handler)
      {
        close();
        return;
      }
    }
    ~ssl_websocket_session();

    void send(const std::string &msg);

    void close(boost::beast::websocket::close_code code = boost::beast::websocket::close_code::normal);

  private:
    boost::optional<ssl_ws_handler &> get_ssl_ws_handler(const std::string &path);

    void on_accept(boost::beast::error_code ec);

    void do_read();
    void on_read(boost::beast::error_code ec, std::size_t bytes_transferred);

    void on_write(boost::beast::error_code ec, std::size_t bytes_transferred);

    void on_close(boost::beast::error_code ec);

  private:
    server &srv;
    boost::beast::flat_buffer buffer;
    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>> ws;
    boost::optional<ssl_ws_handler &> handler;
  };

  class ssl_ws_handler
  {
    friend class ssl_websocket_session;

  public:
    ssl_ws_handler &on_open(std::function<void(ssl_websocket_session &)> handler) noexcept
    {
      on_open_handler = handler;
      return *this;
    }
    ssl_ws_handler &on_close(std::function<void(ssl_websocket_session &)> handler) noexcept
    {
      on_close_handler = handler;
      return *this;
    }
    ssl_ws_handler &on_message(std::function<void(ssl_websocket_session &, const std::string &)> handler) noexcept
    {
      on_message_handler = handler;
      return *this;
    }
    ssl_ws_handler &on_error(std::function<void(ssl_websocket_session &, boost::system::error_code)> handler) noexcept
    {
      on_error_handler = handler;
      return *this;
    }

  private:
    std::function<void(ssl_websocket_session &)> on_open_handler = [](ssl_websocket_session &) {};
    std::function<void(ssl_websocket_session &)> on_close_handler = [](ssl_websocket_session &) {};
    std::function<void(ssl_websocket_session &, const std::string &)> on_message_handler = [](ssl_websocket_session &, const std::string &) {};
    std::function<void(ssl_websocket_session &, boost::system::error_code)> on_error_handler = [](ssl_websocket_session &, boost::system::error_code) {};
  };
} // namespace network