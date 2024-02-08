#pragma once

#include <queue>
#include "base_server.hpp"

#define GET(server, target, handler) server.add_route(boost::beast::http::verb::get, target, std::function{handler})
#define POST(server, target, handler) server.add_route(boost::beast::http::verb::post, target, std::function{handler})
#define PUT(server, target, handler) server.add_route(boost::beast::http::verb::put, target, std::function{handler})
#define DELETE(server, target, handler) server.add_route(boost::beast::http::verb::delete_, target, std::function{handler})

namespace network::async
{
  class plain_session;

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

  template <class Session, class ReqBody, class ResBody>
  class http_handler : public network::http_handler
  {
  public:
    http_handler(const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> &handler) : handler(handler) {}

    void handle_request(network::request &&req) override
    {
      auto &req_impl = static_cast<request_impl<Session, ReqBody> &>(req);
      boost::beast::http::response<ResBody> res{boost::beast::http::status::ok, req_impl.get_request().version()};
      res.set(boost::beast::http::field::server, "ratioNet");
      res.set(boost::beast::http::field::content_type, "text/html");
      res.keep_alive(req_impl.get_request().keep_alive());
      handler(req_impl.get_request(), res);
      req_impl.get_session().enqueue(std::move(res));
    }

  private:
    const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> handler;
  };

  class server : public network::base_server
  {
  public:
    server(const std::string &address = SERVER_ADDRESS, const std::string &port = SERVER_PORT, std::size_t concurrency_hint = std::thread::hardware_concurrency());

    template <class ReqBody, class ResBody>
    void add_route(boost::beast::http::verb method, const std::string &path, const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> &handler) { http_routes[method].emplace_back(std::regex(path), std::make_unique<http_handler<plain_session, ReqBody, ResBody>>(handler)); }

#ifdef USE_SSL
    template <class ReqBody, class ResBody>
    void add_ssl_route(boost::beast::http::verb method, const std::string &path, const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> &handler) { https_routes[method].emplace_back(std::regex(path), std::make_unique<http_handler<ssl_session, ReqBody, ResBody>>(handler)); }
#endif

  private:
    void do_accept() override;
    void on_accept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket);
  };

  class plain_session : public network::http_session, public std::enable_shared_from_this<plain_session>
  {
  public:
    plain_session(network::base_server &srv, boost::beast::tcp_stream &&str, boost::beast::flat_buffer &&buffer) : network::http_session(srv, std::move(str), std::move(buffer)) {}

    void run() override;
    void do_eof() override;

    template <class Body>
    void enqueue(boost::beast::http::response<Body> &&res) { boost::asio::post(stream.get_executor(), boost::beast::bind_front_handler(&plain_session::enqueue_response<Body>, this->shared_from_this(), std::move(res))); }

    template <class Body>
    void do_write(boost::beast::http::response<Body> &res) { boost::beast::http::async_write(stream, res, boost::beast::bind_front_handler(&plain_session::on_write, this->shared_from_this(), res.keep_alive())); }

  private:
    template <class Body>
    void handle_request(boost::beast::http::request<Body> &&req)
    {
      if (auto c_res = check_request(req); c_res)
        return enqueue(std::move(c_res.value()));
      if (auto handler = get_http_handler(req.method(), req.target().to_string()); handler)
        return handler.value().handle_request(request_impl<plain_session, Body>(*this, std::move(req)));
      else
        enqueue(no_handler(req));
    }

    void do_read();
    void on_read(boost::beast::error_code ec, std::size_t bytes_transferred);

    template <class Body>
    void enqueue_response(boost::beast::http::response<Body> &&res)
    {
      response_queue.push(std::make_unique<response_impl<plain_session, Body>>(*this, std::move(res)));

      if (response_queue.size() > 1)
        return; // already sending

      response_queue.front()->do_write();
    }

    void on_write(bool keep_alive, boost::beast::error_code ec, std::size_t bytes_transferred);

  private:
    std::queue<std::unique_ptr<response>> response_queue;
  };

  class plain_websocket_session : public network::plain_websocket_session, public std::enable_shared_from_this<plain_websocket_session>
  {
  public:
    plain_websocket_session(network::base_server &srv, boost::beast::tcp_stream &&str, websocket_handler &handler) : network::plain_websocket_session(srv, std::move(str), handler) {}

    template <class Body>
    void do_accept(boost::beast::http::request<Body> &&req)
    {
      websocket.set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::server));
      websocket.set_option(boost::beast::websocket::stream_base::decorator([](boost::beast::websocket::response_type &res)
                                                                           { res.set(boost::beast::http::field::server, "ratioNet"); }));
      websocket.async_accept(req, boost::beast::bind_front_handler(&plain_websocket_session::on_accept, this->shared_from_this()));
    }

    void send(const std::shared_ptr<const std::string> &msg) override;
    void close(boost::beast::websocket::close_reason const &cr = boost::beast::websocket::close_code::normal) override;

  private:
    void on_accept(boost::beast::error_code ec);

    void do_read();
    void on_read(boost::beast::error_code ec, std::size_t bytes_transferred);

    void enqueue(const std::shared_ptr<const std::string> &msg);

    void do_write();
    void on_write(boost::beast::error_code ec, std::size_t bytes_transferred);

    void on_close(boost::beast::error_code ec);

  private:
    std::queue<std::shared_ptr<const std::string>> send_queue;
  };

#ifdef USE_SSL
  class session_detector : public network::session_detector, public std::enable_shared_from_this<session_detector>
  {
  public:
    session_detector(network::base_server &srv, boost::asio::ip::tcp::socket &&socket, boost::asio::ssl::context &ssl_ctx) : network::session_detector(srv, std::move(socket), ssl_ctx) {}

    void run() override;

  private:
    void on_run();
    void on_detect(boost::beast::error_code ec, bool result);
  };

  class ssl_session : public network::ssl_session, public std::enable_shared_from_this<ssl_session>
  {
  public:
    ssl_session(network::base_server &srv, boost::beast::tcp_stream &&str, boost::asio::ssl::context &ssl_ctx, boost::beast::flat_buffer &&buffer) : network::ssl_session(srv, std::move(str), ssl_ctx, std::move(buffer)) {}

    void run() override;
    void do_eof() override;

    template <class Body>
    void enqueue(boost::beast::http::response<Body> &&res) { boost::asio::post(stream.get_executor(), boost::beast::bind_front_handler(&ssl_session::enqueue_response<Body>, this->shared_from_this(), std::move(res))); }

    template <class Body>
    void do_write(boost::beast::http::response<Body> &res) { boost::beast::http::async_write(stream, res, boost::beast::bind_front_handler(&ssl_session::on_write, this->shared_from_this(), res.keep_alive())); }

  private:
    void on_handshake(boost::beast::error_code ec, std::size_t bytes_used);

    template <class Body>
    void handle_request(boost::beast::http::request<Body> &&req)
    {
      if (auto c_res = check_request(req); c_res)
        return enqueue(std::move(c_res.value()));
      if (auto handler = get_https_handler(req.method(), req.target().to_string()); handler)
        return handler.value().handle_request(request_impl<ssl_session, Body>(*this, std::move(req)));
      else
        enqueue(no_handler(req));
    }

    void do_read();
    void on_read(boost::beast::error_code ec, std::size_t bytes_transferred);

    template <class Body>
    void enqueue_response(boost::beast::http::response<Body> &&res)
    {
      response_queue.push(std::make_unique<response_impl<ssl_session, Body>>(*this, std::move(res)));

      if (response_queue.size() > 1)
        return; // already sending

      response_queue.front()->do_write();
    }

    void on_write(bool keep_alive, boost::beast::error_code ec, std::size_t bytes_transferred);

    void on_shutdown(boost::beast::error_code ec);

  private:
    std::queue<std::unique_ptr<response>> response_queue;
  };

  class ssl_websocket_session : public network::ssl_websocket_session, public std::enable_shared_from_this<ssl_websocket_session>
  {
  public:
    ssl_websocket_session(network::base_server &srv, boost::beast::ssl_stream<boost::beast::tcp_stream> &&str, websocket_handler &handler) : network::ssl_websocket_session(srv, std::move(str), handler) {}

    template <class Body>
    void do_accept(boost::beast::http::request<Body> &&req)
    {
      websocket.set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::server));
      websocket.set_option(boost::beast::websocket::stream_base::decorator([](boost::beast::websocket::response_type &res)
                                                                           { res.set(boost::beast::http::field::server, "ratioNet"); }));
      websocket.async_accept(req, boost::beast::bind_front_handler(&ssl_websocket_session::on_accept, this->shared_from_this()));
    }

    void send(const std::shared_ptr<const std::string> &msg) override;
    void close(boost::beast::websocket::close_reason const &cr = boost::beast::websocket::close_code::normal) override;

  private:
    void on_accept(boost::beast::error_code ec);

    void do_read();
    void on_read(boost::beast::error_code ec, std::size_t bytes_transferred);

    void enqueue(const std::shared_ptr<const std::string> &msg);

    void do_write();
    void on_write(boost::beast::error_code ec, std::size_t bytes_transferred);

    void on_close(boost::beast::error_code ec);

  private:
    std::queue<std::shared_ptr<const std::string>> send_queue;
  };
#endif
} // namespace network::async