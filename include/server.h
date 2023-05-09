#pragma once

#include <boost/beast.hpp>
#include <regex>

namespace network
{
  class server
  {
  public:
    server(std::string address = "0.0.0.0", unsigned short port = 8080);

    void add_route(boost::beast::http::verb method, std::string regex, std::function<void(boost::beast::http::request<boost::beast::http::string_body> &, boost::beast::http::response<boost::beast::http::string_body> &)> callback);

    void run();

  private:
    void do_accept();

  private:
    boost::asio::io_context ctx;
    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::socket socket;
    std::vector<std::pair<std::regex, std::function<void(boost::beast::http::request<boost::beast::http::string_body> &, boost::beast::http::response<boost::beast::http::string_body> &)>>> get_routes, post_routes, put_routes, delete_routes;
  };
} // namespace network
