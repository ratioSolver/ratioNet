#pragma once

#include <boost/asio.hpp>
#include <queue>

namespace network
{
  class server;
  class session;

  class ws_session : public std::enable_shared_from_this<ws_session>
  {
    friend class server;
    friend class session;

  public:
    ws_session(server &srv, boost::asio::ip::tcp::socket &&socket);
    ~ws_session();

  private:
    void read();
    void enqueue(std::unique_ptr<std::string> res);
    void write();

    void on_read(const boost::system::error_code &ec, std::size_t bytes_transferred);
    void on_write(const boost::system::error_code &ec, std::size_t bytes_transferred);

  private:
    server &srv;
    boost::asio::ip::tcp::socket socket;
    boost::asio::streambuf input_buffer;
    std::queue<std::unique_ptr<std::string>> res_queue;
  };
} // namespace network
