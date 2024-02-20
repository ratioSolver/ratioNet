#pragma once

#include <thread>
#include <regex>
#include "http_handler.hpp"
#include "websocket_handler.hpp"

#define GET(server, target, handler) server.add_route(boost::beast::http::verb::get, target, std::function{handler})
#define POST(server, target, handler) server.add_route(boost::beast::http::verb::post, target, std::function{handler})
#define PUT(server, target, handler) server.add_route(boost::beast::http::verb::put, target, std::function{handler})
#define DELETE(server, target, handler) server.add_route(boost::beast::http::verb::delete_, target, std::function{handler})

namespace network
{
  template <class Session, class ReqBody, class ResBody>
  class http_handler : public base_http_handler
  {
  public:
    http_handler(const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> &handler) : handler(handler) {}

    void handle_request(request &&req) override
    {
      auto &req_impl = static_cast<request_impl<Session, ReqBody> &>(req);
      boost::beast::http::response<ResBody> res{boost::beast::http::status::ok, req_impl.get_request().version()};
      res.set(boost::beast::http::field::server, "ratioNet");
      res.set(boost::beast::http::field::content_type, "text/html");
      res.keep_alive(req_impl.get_request().keep_alive());
      handler(req_impl.get_request(), res);
    }

  private:
    const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> handler;
  };

  class base_server
  {
    friend class base_http_session;

  public:
    base_server(const std::string &address = SERVER_ADDRESS, const std::string &port = SERVER_PORT, std::size_t concurrency_hint = std::thread::hardware_concurrency());

    void set_log_handler(std::function<void(const std::string &)> handler) { log_handler = handler; }
    void set_error_handler(std::function<void(const std::string &)> handler) { error_handler = handler; }

    void start();
    void stop();

    template <class ReqBody, class ResBody>
    void add_route(boost::beast::http::verb method, const std::string &path, const std::function<void(const boost::beast::http::request<ReqBody> &, boost::beast::http::response<ResBody> &)> &handler) { http_routes[method].emplace_back(std::regex(path), std::make_unique<http_handler<http_session, ReqBody, ResBody>>(handler)); }
    websocket_handler &ws(const std::string &target) { return *ws_routes.emplace_back(std::regex(target), std::make_unique<websocket_handler>()).second; }

  private:
    boost::optional<base_http_handler &> get_http_handler(boost::beast::http::verb method, const std::string &target);
    boost::optional<websocket_handler &> get_ws_handler(const std::string &target);

  private:
    void do_accept();
    void on_accept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket);

  private:
    boost::asio::io_context io_ctx;          // The io_context is required for all I/O
    std::vector<std::thread> threads;        // The thread pool
    boost::asio::signal_set signals;         // The signal_set is used to register for process termination notifications
    boost::asio::ip::tcp::endpoint endpoint; // The endpoint for the server
    boost::asio::ip::tcp::acceptor acceptor; // The acceptor receives incoming connections
    std::unordered_map<boost::beast::http::verb, std::vector<std::pair<std::regex, std::unique_ptr<base_http_handler>>>> http_routes;
    std::vector<std::pair<std::regex, std::unique_ptr<websocket_handler>>> ws_routes;

  protected:
    std::function<void(const std::string &)> log_handler = [](const std::string &) {};
    std::function<void(const std::string &)> error_handler = [](const std::string &) {};
  };

  class server : public base_server
  {
  public:
    server(const std::string &address = SERVER_ADDRESS, const std::string &port = SERVER_PORT, std::size_t concurrency_hint = std::thread::hardware_concurrency());
  };
} // namespace network
