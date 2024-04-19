#pragma once

#include <boost/asio.hpp>
#include <queue>
#include "request.hpp"
#include "response.hpp"

namespace network
{
  class server;

  class session : public std::enable_shared_from_this<session>
  {
  public:
    session(server &srv, boost::asio::ip::tcp::socket socket);

    void read();

  private:
    void on_read(const boost::system::error_code &ec, std::size_t bytes_transferred);
    void on_body(const boost::system::error_code &ec, std::size_t bytes_transferred);

  private:
    server &srv;
    boost::asio::ip::tcp::socket socket;
    boost::asio::streambuf buffer;
    std::unique_ptr<request> req;
    std::queue<boost::asio::const_buffer> res;
  };
} // namespace network
