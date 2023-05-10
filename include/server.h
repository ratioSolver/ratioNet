#pragma once

#include "http_session.h"
#include "websocket_session.h"
#include <boost/beast.hpp>
#include <regex>
#include <unordered_set>

namespace network
{
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

    void start();

  private:
    void on_accept(boost::system::error_code ec);

  private:
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::socket socket;
    std::vector<std::pair<std::regex, std::function<void(request &, response &)>>> get_routes, post_routes, put_routes, delete_routes;
    std::unordered_set<websocket_session *> sessions;
  };
} // namespace network
