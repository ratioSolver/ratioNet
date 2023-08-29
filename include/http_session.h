#pragma once

#include "memory.h"
#include <boost/beast.hpp>
#include <queue>

namespace network
{
  class server;
  class http_work;
  using http_work_ptr = utils::u_ptr<http_work>;

  class http_session
  {
  public:
    http_session(server &srv, boost::beast::tcp_stream &&stream, boost::beast::flat_buffer &&buffer, size_t queue_limit = 8);

  private:
    void do_read(); // Start reading a request

    void on_read(boost::beast::error_code ec, std::size_t bytes_transferred);
    void on_write(boost::beast::error_code ec, std::size_t bytes_transferred, bool close);

    void do_eof();

  private:
    server &srv;
    boost::beast::tcp_stream stream;
    boost::beast::flat_buffer buffer;
    boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser;
    const size_t queue_limit;             // The limit on the allowed size of the queue
    std::queue<http_work_ptr> work_queue; // This queue is used for the work that is to be done on the session
  };

  class http_work
  {
    friend class http_session;

  private:
    http_work(http_session &session);

  private:
    http_session &session;
  };
} // namespace network
