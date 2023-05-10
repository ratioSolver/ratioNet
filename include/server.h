#pragma once

#include "http_session.h"
#include "websocket_session.h"
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <regex>
#include <unordered_set>

namespace network
{
  class ws_handlers
  {
    friend class websocket_session;

  public:
    ws_handlers &on_open(std::function<void(websocket_session &)> handler) noexcept
    {
      on_open_handler = handler;
      return *this;
    }
    ws_handlers &on_close(std::function<void(websocket_session &)> handler) noexcept
    {
      on_close_handler = handler;
      return *this;
    }
    ws_handlers &on_message(std::function<void(websocket_session &, const std::string &)> handler) noexcept
    {
      on_message_handler = handler;
      return *this;
    }

  private:
    std::function<void(websocket_session &)> on_open_handler = [](websocket_session &) {};
    std::function<void(websocket_session &)> on_close_handler = [](websocket_session &) {};
    std::function<void(websocket_session &, const std::string &)> on_message_handler = [](websocket_session &, const std::string &) {};
  };

  class server
  {
    friend class http_session;
    friend class websocket_session;

  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080);

    void add_route(boost::beast::http::verb method, const std::string &path, std::function<void(request &, response &)> handler) noexcept
    {
      switch (method)
      {
      case boost::beast::http::verb::get:
        get_routes.push_back(std::make_pair(std::regex(path), handler));
        break;
      case boost::beast::http::verb::post:
        post_routes.push_back(std::make_pair(std::regex(path), handler));
        break;
      case boost::beast::http::verb::put:
        put_routes.push_back(std::make_pair(std::regex(path), handler));
        break;
      case boost::beast::http::verb::delete_:
        delete_routes.push_back(std::make_pair(std::regex(path), handler));
        break;
      default:
        break;
      }
    }

    ws_handlers &add_route(const std::string &path) noexcept
    {
      ws_routes.push_back(std::make_pair(std::regex(path), ws_handlers()));
      return ws_routes.back().second;
    }

    void start();
    void stop();

  private:
    void on_accept(boost::system::error_code ec);

  private:
    boost::asio::io_context io_context;
    boost::asio::signal_set signals;
    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::socket socket;
    std::vector<std::pair<std::regex, std::function<void(request &, response &)>>> get_routes, post_routes, put_routes, delete_routes;
    std::vector<std::pair<std::regex, ws_handlers>> ws_routes;
    std::unordered_set<websocket_session *> sessions;
  };
} // namespace network
