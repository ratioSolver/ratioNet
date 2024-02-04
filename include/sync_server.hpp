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

  class session_detector : public network::session_detector
  {
  public:
    session_detector(network::server &srv, boost::asio::ip::tcp::socket &&socket) : network::session_detector(srv, std::move(socket)) {}

    void run() override;

  private:
    void on_run();
  };

  class plain_session : public network::http_session
  {
  public:
    plain_session(network::server &srv, boost::beast::flat_buffer &&buffer) : network::http_session(srv, std::move(buffer)) {}

    void run() override;

  private:
    void do_read() override;
  };

  class ssl_session : public network::http_session
  {
  public:
    ssl_session(network::server &srv, boost::beast::flat_buffer &&buffer) : network::http_session(srv, std::move(buffer)) {}

    void run() override;

  private:
    void do_read() override;
  };
} // namespace network
