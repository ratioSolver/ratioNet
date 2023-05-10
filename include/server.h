#pragma once

#include "websocket_session.h"
#include <boost/beast.hpp>
#include <regex>
#include <unordered_set>

namespace network
{
  class server
  {
    friend class websocket_session;

  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080);

    void start();

  private:
    void on_accept(boost::system::error_code ec);

  private:
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::socket socket;
    std::unordered_set<websocket_session *> sessions;
  };
} // namespace network
