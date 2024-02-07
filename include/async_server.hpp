#pragma once

#include <queue>
#include "server.hpp"

namespace network::async
{
  template <class ReqBody, class ResBody>
  class plain_handler;
#ifdef USE_SSL
  template <class ReqBody, class ResBody>
  class ssl_handler;
#endif

  class server_response
  {
  public:
    virtual ~server_response() = default;

    virtual void do_write() = 0;
  };

  template <class Session, class Body>
  class server_response_impl : public server_response
  {
  public:
    server_response_impl(Session &session, boost::beast::http::response<Body> &&res) : session(session), res(std::move(res)) {}

    void do_write() override { session.do_write(res); }

  public:
    Session &session;
    boost::beast::http::response<Body> res;
  };

  class server : public network::server
  {
  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080, std::size_t concurrency_hint = std::thread::hardware_concurrency());

    template <class ReqBody, class ResBody>
    void get(const std::string &path, const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> &handler) { add_route(boost::beast::http::verb::get, path, handler); }

    template <class ReqBody, class ResBody>
    void post(const std::string &path, const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> &handler) { add_route(boost::beast::http::verb::post, path, handler); }

    template <class ReqBody, class ResBody>
    void put(const std::string &path, const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> &handler) { add_route(boost::beast::http::verb::put, path, handler); }

    template <class ReqBody, class ResBody>
    void del(const std::string &path, const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> &handler) { add_route(boost::beast::http::verb::delete_, path, handler); }

    template <class ReqBody, class ResBody>
    void add_route(boost::beast::http::verb method, const std::string &path, const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> &handler) { http_routes[method].emplace_back(std::regex(path), std::make_unique<plain_handler<ReqBody, ResBody>>(handler)); }

#ifdef USE_SSL
    template <class ReqBody, class ResBody>
    void add_ssl_route(boost::beast::http::verb method, const std::string &path, const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> &handler) { https_routes[method].emplace_back(std::regex(path), std::make_unique<ssl_handler<ReqBody, ResBody>>(handler)); }
#endif

  private:
    void do_accept() override;
    void on_accept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket);
  };

#ifdef USE_SSL
  class session_detector : public network::session_detector, public std::enable_shared_from_this<session_detector>
  {
  public:
    session_detector(network::server &srv, boost::asio::ip::tcp::socket &&socket, boost::asio::ssl::context &ctx) : network::session_detector(srv, std::move(socket), ctx) {}

    void run() override;

  private:
    void on_run();
    void on_detect(boost::beast::error_code ec, bool result);
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

  class plain_session : public network::plain_session, public std::enable_shared_from_this<plain_session>
  {
  public:
    plain_session(network::server &srv, boost::beast::tcp_stream &&str, boost::beast::flat_buffer &&buffer) : network::plain_session(srv, std::move(str), std::move(buffer)) {}

    void run() override;
    void do_eof() override;

    template <class Body>
    void enqueue(boost::beast::http::response<Body> &&res) { boost::asio::post(stream.get_executor(), boost::beast::bind_front_handler(&plain_session::enqueue_response<Body>, this->shared_from_this(), std::move(res))); }

    template <class Body>
    void do_write(boost::beast::http::response<Body> &res) { boost::beast::http::async_write(stream, res, boost::beast::bind_front_handler(&plain_session::on_write, this->shared_from_this(), res.keep_alive())); }

  private:
    void do_read();
    void on_read(boost::beast::error_code ec, std::size_t bytes_transferred);

    template <class Body>
    void handle_request(boost::beast::http::request<Body> &&req)
    {
      if (auto c_res = check_request(req); c_res)
        return enqueue(std::move(c_res.value()));
      if (auto handler = get_http_handler(req.method(), req.target().to_string()); handler)
        return handler.value().handle_request(server_request<Body>(std::move(req)));
      else
        enqueue(no_handler(req));
    }

    template <class Body>
    void enqueue_response(boost::beast::http::response<Body> &&res)
    {
      response_queue.push(std::make_unique<server_response_impl<plain_session, Body>>(*this, std::move(res)));

      if (response_queue.size() > 1)
        return; // already sending

      response_queue.front()->do_write();
    }

    void on_write(bool keep_alive, boost::beast::error_code ec, std::size_t bytes_transferred);

  private:
    std::queue<std::unique_ptr<server_response>> response_queue;
  };

  template <class ReqBody, class ResBody>
  class plain_handler : public http_handler
  {
  public:
    plain_handler(const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> &handler) : handler(handler) {}

    void handle_request(network::server_request &&req) override
    {
      auto &req_impl = static_cast<server_request_impl<plain_session, ReqBody> &>(req);
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

  class plain_websocket_session : public network::plain_websocket_session, public std::enable_shared_from_this<plain_websocket_session>
  {
  public:
    plain_websocket_session(network::server &srv, boost::beast::tcp_stream &&str, websocket_handler &handler) : network::plain_websocket_session(srv, std::move(str), handler) {}

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
  class ssl_session : public network::ssl_session, public std::enable_shared_from_this<ssl_session>
  {
  public:
    ssl_session(network::server &srv, boost::beast::tcp_stream &&str, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&buffer) : network::ssl_session(srv, std::move(str), ctx, std::move(buffer)) {}

    void run() override;
    void do_eof() override;

    template <class Body>
    void enqueue(boost::beast::http::response<Body> &&res) { boost::asio::post(stream.get_executor(), boost::beast::bind_front_handler(&ssl_session::enqueue_response<Body>, this->shared_from_this(), std::move(res))); }

    template <class Body>
    void do_write(boost::beast::http::response<Body> &res) { boost::beast::http::async_write(stream, res, boost::beast::bind_front_handler(&ssl_session::on_write, this->shared_from_this(), res.keep_alive())); }

  private:
    void on_handshake(boost::beast::error_code ec, std::size_t bytes_used);
    void on_shutdown(boost::beast::error_code ec);

    void do_read();
    void on_read(boost::beast::error_code ec, std::size_t bytes_transferred);

    template <class Body>
    void handle_request(boost::beast::http::request<Body> &&req)
    {
      if (auto c_res = check_request(req); c_res)
        return enqueue(std::move(c_res.value()));
      if (auto handler = get_https_handler(req.method(), req.target().to_string()); handler)
        return handler.value().handle_request(server_request<Body>(std::move(req)));
      else
        enqueue(no_handler(req));
    }

    template <class Body>
    void enqueue_response(boost::beast::http::response<Body> &&res)
    {
      response_queue.push(std::make_unique<server_response_impl<ssl_session, Body>>(*this, std::move(res)));

      if (response_queue.size() > 1)
        return; // already sending

      response_queue.front()->do_write();
    }

    void on_write(bool keep_alive, boost::beast::error_code ec, std::size_t bytes_transferred);

  private:
    std::queue<std::unique_ptr<server_response>> response_queue;
  };

  template <class ReqBody, class ResBody>
  class ssl_handler : public http_handler
  {
  public:
    ssl_handler(const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> &handler) : handler(handler) {}

    void handle_request(network::server_request &&req) override
    {
      auto &req_impl = static_cast<server_request_impl<ssl_session, ReqBody> &>(req);
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

  class ssl_websocket_session : public network::ssl_websocket_session, public std::enable_shared_from_this<ssl_websocket_session>
  {
  public:
    ssl_websocket_session(network::server &srv, boost::beast::ssl_stream<boost::beast::tcp_stream> &&str, websocket_handler &handler) : network::ssl_websocket_session(srv, std::move(str), handler) {}

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
} // namespace network
