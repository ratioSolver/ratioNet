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
    friend class server;

  public:
    session(server &srv, boost::asio::ip::tcp::socket socket);

  private:
    void read();
    void enqueue(const response &res);
    void write();

    void on_read(const boost::system::error_code &ec, std::size_t bytes_transferred);
    void on_body(const boost::system::error_code &ec, std::size_t bytes_transferred);

    void on_write(const boost::system::error_code &ec, std::size_t bytes_transferred);

  private:
    server &srv;
    boost::asio::ip::tcp::socket socket;
    boost::asio::streambuf buffer;
    request req;
    std::queue<boost::asio::const_buffer> res;
  };
} // namespace network
