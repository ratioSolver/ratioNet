#pragma once

#include "server.hpp"

namespace network::async
{
  class server : public network::server
  {
  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080, std::size_t concurrency_hint = std::thread::hardware_concurrency());

  private:
    void do_accept() override;
    void on_accept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket);
  };

#ifdef USE_SSL
  class session_detector : public network::session_detector, public std::enable_shared_from_this<session_detector>
  {
  public:
    session_detector(network::server &srv, boost::asio::ip::tcp::socket &&socket, boost::asio::ssl::context &ctx) : network::session_detector(srv, std::move(socket), ctx) {}

    void run() override;

  private:
    void on_run();
    void on_detect(boost::beast::error_code ec, bool result);
  };
#endif

  class plain_session : public network::plain_session, public std::enable_shared_from_this<plain_session>
  {
  public:
    plain_session(network::server &srv, boost::beast::tcp_stream &&str, boost::beast::flat_buffer &&buffer) : network::plain_session(srv, std::move(str), std::move(buffer)) {}

    void run() override;
    void do_eof() override;

  private:
    void do_read();
    void on_read(boost::beast::error_code ec, std::size_t bytes_transferred);
  };

  class plain_websocket_session : public network::plain_websocket_session
  {
  public:
    plain_websocket_session(network::server &srv, boost::beast::tcp_stream &&str, websocket_handler &handler) : network::plain_websocket_session(srv, std::move(str), handler) {}
  };

#ifdef USE_SSL
  class ssl_session : public network::ssl_session, public std::enable_shared_from_this<ssl_session>
  {
  public:
    ssl_session(network::server &srv, boost::beast::tcp_stream &&str, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&buffer) : network::ssl_session(srv, std::move(str), ctx, std::move(buffer)) {}

    void run() override;
    void do_eof() override;

  private:
    void on_handshake(boost::beast::error_code ec, std::size_t bytes_used);
    void on_shutdown(boost::beast::error_code ec);

    void do_read();
    void on_read(boost::beast::error_code ec, std::size_t bytes_transferred);
  };

  class ssl_websocket_session : public network::ssl_websocket_session
  {
  public:
    ssl_websocket_session(network::server &srv, boost::beast::ssl_stream<boost::beast::tcp_stream> &&str, websocket_handler &handler) : network::ssl_websocket_session(srv, std::move(str), handler) {}
  };
#endif
} // namespace network
