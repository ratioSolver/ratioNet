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
    void add_websocket_route(std::string regex, std::function<void(boost::beast::http::request<boost::beast::http::string_body> &, boost::beast::websocket::stream<boost::beast::tcp_stream> &)> callback);

    void run();

  private:
    void do_accept();

    void handle_http_request(boost::beast::http::request<boost::beast::http::string_body> &request, boost::beast::http::response<boost::beast::http::string_body> &response);
    void handle_websocket_request(boost::beast::http::request<boost::beast::http::string_body> &request, boost::beast::websocket::stream<boost::beast::tcp_stream> &websocket);

  private:
    boost::asio::io_context ctx;
    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::socket socket;
    std::vector<std::pair<std::regex, std::function<void(boost::beast::http::request<boost::beast::http::string_body> &, boost::beast::http::response<boost::beast::http::string_body> &)>>> get_routes, post_routes, put_routes, delete_routes;
    std::vector<std::pair<std::regex, std::function<void(boost::beast::http::request<boost::beast::http::string_body> &, boost::beast::websocket::stream<boost::beast::tcp_stream> &)>>> websocket_routes;
  };
} // namespace network
