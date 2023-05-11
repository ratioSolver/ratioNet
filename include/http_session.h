#pragma once

#include <boost/beast.hpp>

namespace network
{
  class server;
  using request = boost::beast::http::request<boost::beast::http::dynamic_body>;
  using response = boost::beast::http::response<boost::beast::http::string_body>;

  class http_session
  {
  public:
    http_session(server &srv, boost::asio::ip::tcp::socket &&socket);
    ~http_session();

    void run();

  private:
    void on_read(boost::system::error_code ec, std::size_t bytes_transferred);
    void on_write(boost::system::error_code ec, std::size_t bytes_transferred, bool close);

  private:
    server &srv;
    boost::asio::ip::tcp::socket socket;
    boost::beast::flat_buffer buffer;
    request req;
  };
} // namespace network
