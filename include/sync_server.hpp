#pragma once

#include "server.hpp"

namespace network::sync
{
  class session_detector : public network::session_detector
  {
  public:
    session_detector(server &srv, boost::asio::ip::tcp::socket &&socket) : network::session_detector(srv, std::move(socket)) {}

    void run() override;
  };

  class server : public network::server
  {
  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080, std::size_t concurrency_hint = std::thread::hardware_concurrency());

  private:
    void do_accept() override;
  };
} // namespace network
