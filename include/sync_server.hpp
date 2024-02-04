#pragma once

#include "server.hpp"
#include <unordered_set>

namespace network::sync
{
  class session_detector;

  class server : public network::server
  {
    friend class session_detector;

  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080, std::size_t concurrency_hint = std::thread::hardware_concurrency());

  private:
    void do_accept() override;

  private:
    std::unordered_set<std::unique_ptr<network::http_session>> sessions;
  };

#ifdef USE_SSL
  class session_detector : public network::session_detector
  {
  public:
    session_detector(network::server &srv, boost::asio::ip::tcp::socket &&socket, boost::asio::ssl::context &ctx) : network::session_detector(srv, std::move(socket), ctx) {}

    void run() override;

  private:
    void on_run();
  };
#endif

  class plain_session : public network::plain_session
  {
  public:
    plain_session(network::server &srv, boost::beast::tcp_stream &&str, boost::beast::flat_buffer &&buffer) : network::plain_session(srv, std::move(str), std::move(buffer)) {}

    void run() override;

  private:
    void do_read() override;
  };

#ifdef USE_SSL
  class ssl_session : public network::ssl_session
  {
  public:
    ssl_session(network::server &srv, boost::beast::tcp_stream &&str, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&buffer) : network::ssl_session(srv, std::move(str), ctx, std::move(buffer)) {}

    void run() override;

  private:
    void do_read() override;
  };
#endif
} // namespace network
