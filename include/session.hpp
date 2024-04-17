#pragma once

#include <boost/asio.hpp>
#include "request.hpp"

namespace network
{
  class server;

  class session : public std::enable_shared_from_this<session>
  {
  public:
    session(server &srv, boost::asio::ip::tcp::socket socket);

    void start();

  private:
    void on_read(const boost::system::error_code &ec, std::size_t bytes_transferred);
    void on_body(const boost::system::error_code &ec, std::size_t bytes_transferred);

  private:
    server &srv;
    boost::asio::ip::tcp::socket socket;
    boost::asio::streambuf buffer;
    std::unique_ptr<request> req;
  };
} // namespace network
