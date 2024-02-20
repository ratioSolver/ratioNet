#pragma once

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <queue>
#include <memory>

namespace network
{
  class base_server;

  class response
  {
  public:
    virtual ~response() = default;

    virtual void do_write() = 0;
  };

  template <class Session, class Body>
  class response_impl : public response
  {
  public:
    response_impl(Session &session, boost::beast::http::response<Body> &&res) : session(session), res(std::move(res)) {}

    void do_write() override { session.do_write(res); }

  public:
    Session &session;
    boost::beast::http::response<Body> res;
  };

  class base_http_session
  {
  public:
    base_http_session(base_server &srv);
    virtual ~base_http_session() = default;

    virtual void run() = 0;
    virtual void do_eof() = 0;

  protected:
    void fire_on_error(const boost::beast::error_code &ec);

  private:
    base_server &srv;
  };

  class http_session : public base_http_session, public std::enable_shared_from_this<http_session>
  {
  public:
    http_session(base_server &srv, boost::asio::ip::tcp::socket &&socket);

    void run() override;
    void do_eof() override;

  private:
    void do_read();
    void on_read(boost::beast::error_code ec, std::size_t bytes_transferred);

  private:
    boost::beast::tcp_stream stream;
    boost::beast::flat_buffer buffer;
    boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser;
    std::queue<std::unique_ptr<response>> response_queue;
  };
} // namespace network
