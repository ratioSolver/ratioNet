#pragma once

#include "server.hpp"
#include <unordered_set>

namespace network::sync
{
#ifdef USE_SSL
  class session_detector;
#endif

  class server : public network::server
  {
#ifdef USE_SSL
    friend class session_detector;
    friend class ssl_session;
#endif
    friend class plain_session;

  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080, std::size_t concurrency_hint = std::thread::hardware_concurrency());

  private:
    void do_accept() override;

  private:
    std::unordered_set<std::unique_ptr<network::http_session>> sessions;
    std::unordered_set<std::unique_ptr<network::websocket_session>> ws_sessions;
  };

#ifdef USE_SSL
  class session_detector : public network::session_detector
  {
  public:
    session_detector(network::server &srv, boost::asio::ip::tcp::socket &&socket, boost::asio::ssl::context &ctx) : network::session_detector(srv, std::move(socket), ctx) {}

    void run() override;

  private:
    void on_run();
  };
#endif

  template <class Body>
  class server_request : public network::server_request
  {
  public:
    server_request(boost::beast::http::request<Body> &&req) : req(std::move(req)) {}
    virtual ~server_request() = default;

    boost::beast::http::request<Body> &get() { return req; }

  private:
    boost::beast::http::request<Body> req;
  };

  class plain_session : public network::plain_session
  {
  public:
    plain_session(network::server &srv, boost::beast::tcp_stream &&str, boost::beast::flat_buffer &&buffer) : network::plain_session(srv, std::move(str), std::move(buffer)) {}

    void run() override;
    void do_eof() override;

  private:
    template <class Body>
    void handle_request(boost::beast::http::request<Body> &&req)
    {
      if (auto c_res = check_request(req); c_res)
        return write(std::move(c_res.value()));
      if (auto handler = get_http_handler(req.method(), req.target().to_string()); handler)
        return handler.value().handle_request(server_request<Body>(std::move(req)));
      else
        write(no_handler(req));
    }

    template <class Body>
    void write(boost::beast::http::response<Body> &&res)
    {
      boost::beast::error_code ec;
      boost::beast::http::write(stream, res, ec);
      if (ec)
        throw std::runtime_error(ec.message());
    }
  };

  class plain_websocket_session : public network::plain_websocket_session
  {
  public:
    plain_websocket_session(network::server &srv, boost::beast::tcp_stream &&str, websocket_handler &handler) : network::plain_websocket_session(srv, std::move(str), handler) {}

    template <class Body>
    void do_accept(boost::beast::http::request<Body> &&req)
    {
      websocket.set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::server));
      websocket.set_option(boost::beast::websocket::stream_base::decorator([](boost::beast::websocket::response_type &res)
                                                                           { res.set(boost::beast::http::field::server, "ratioNet"); }));
      websocket.accept(req);
    }

    void send(const std::shared_ptr<const std::string> &msg) override;
    void close(boost::beast::websocket::close_reason const &cr = boost::beast::websocket::close_code::normal) override;
  };

#ifdef USE_SSL
  class ssl_session : public network::ssl_session
  {
  public:
    ssl_session(network::server &srv, boost::beast::tcp_stream &&str, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&buffer) : network::ssl_session(srv, std::move(str), ctx, std::move(buffer)) {}

    void run() override;
    void do_eof() override;

  private:
    template <class Body>
    void handle_request(boost::beast::http::request<Body> &&req)
    {
      if (auto c_res = check_request(req); c_res)
        return write(std::move(c_res.value()));
      if (auto handler = get_https_handler(req.method(), req.target().to_string()); handler)
        return handler.value().handle_request(server_request<Body>(std::move(req)));
      else
        write(no_handler(req));
    }

    template <class Body>
    void write(boost::beast::http::response<Body> &&res)
    {
      boost::beast::error_code ec;
      boost::beast::http::write(stream, res, ec);
      if (ec)
        throw std::runtime_error(ec.message());
    }
  };

  class ssl_websocket_session : public network::ssl_websocket_session
  {
  public:
    ssl_websocket_session(network::server &srv, boost::beast::ssl_stream<boost::beast::tcp_stream> &&str, websocket_handler &handler) : network::ssl_websocket_session(srv, std::move(str), handler) {}

    template <class Body>
    void do_accept(boost::beast::http::request<Body> &&req)
    {
      websocket.set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::server));
      websocket.set_option(boost::beast::websocket::stream_base::decorator([](boost::beast::websocket::response_type &res)
                                                                           { res.set(boost::beast::http::field::server, "ratioNet"); }));
      websocket.accept(req);
    }

    void send(const std::shared_ptr<const std::string> &msg) override;
    void close(boost::beast::websocket::close_reason const &cr = boost::beast::websocket::close_code::normal) override;
  };
#endif
} // namespace network::sync
