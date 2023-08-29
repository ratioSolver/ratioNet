#pragma once

#include "memory.h"
#include "server.h"
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/ssl.hpp>
#include <queue>

namespace network
{
  class server;
  class ssl_http_work;
  using ssl_http_work_ptr = utils::u_ptr<ssl_http_work>;

  class ssl_http_session
  {
    friend class ssl_http_work;

  public:
    ssl_http_session(server &srv, boost::beast::tcp_stream &&stream, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&buffer, size_t queue_limit = 8);

  private:
    void on_handshake(boost::beast::error_code ec); // Perform the SSL handshake
    void do_read();                                 // Start reading a request

    void on_read(boost::beast::error_code ec, std::size_t bytes_transferred);
    void on_write(boost::beast::error_code ec, std::size_t bytes_transferred, bool close);

    void do_eof();
    void on_shutdown(boost::beast::error_code ec);

  private:
    server &srv;
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream;
    boost::beast::flat_buffer buffer;
    boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser;
    const size_t queue_limit;                 // The limit on the allowed size of the queue
    std::queue<ssl_http_work_ptr> work_queue; // This queue is used for the work that is to be done on the session
  };

  class ssl_http_work
  {
    friend class ssl_http_session;

  public:
    ssl_http_work(ssl_http_session &session) : session(session) {}
    virtual ~ssl_http_work() = default;

  private:
    virtual void do_work() = 0;

  protected:
    template <class Body, class Fields>
    void handle_request(boost::beast::http::request<Body, Fields> &&req) { session.srv.handle_request(session, std::move(req)); }

  private:
    ssl_http_session &session;
  };

  template <class Body, class Fields>
  class ssl_http_work_impl : public ssl_http_work
  {
  public:
    ssl_http_work_impl(ssl_http_session &session, boost::beast::http::request<Body, Fields> &&req) : ssl_http_work(session), req(std::move(req)) {}

  private:
    void do_work() override { handle_request(std::move(req)); }

  private:
    boost::beast::http::request<Body, Fields> req;
  };
} // namespace network
