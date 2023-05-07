#pragma once

#include "request.h"
#include "response.h"
#include <boost/asio.hpp>
#include <regex>

namespace network
{
  class server
  {
  public:
    RATIONET_EXPORT server(short port = 8080);

    RATIONET_EXPORT void add_route(method m, std::regex path, std::function<response_ptr(request &)> callback);

    RATIONET_EXPORT void bind(std::string address, short port);
    RATIONET_EXPORT void start();
    RATIONET_EXPORT void stop();

  private:
    void start_accept();

    request parse_request(boost::asio::ip::tcp::socket &socket);
    response_ptr handle_request(request &req);

  private:
    boost::asio::io_service io_service;
    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::socket socket;
    std::vector<std::pair<std::regex, std::function<response_ptr(request &)>>> get_routes, post_routes, put_routes, delete_routes;
  };
} // namespace network