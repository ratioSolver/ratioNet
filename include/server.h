#pragma once

#include "http_session.h"
#include "ssl_http_session.h"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <functional>
#include <regex>
#include <thread>

namespace network
{
  template <class Session>
  class request_handler
  {
    friend class http_session;
    friend class ssl_http_session;

  public:
    request_handler(Session &session) : session(session) {}
    virtual ~request_handler() = default;

  private:
    virtual void handle_request() = 0;

  protected:
    template <class Body, class Fields>
    void handle_req(boost::beast::http::request<Body, Fields> &&req) { session.srv.handle_request(session, std::move(req)); }

  private:
    Session &session;
  };

  template <class Session, class Body, class Fields>
  class request_handler_impl : public request_handler<Session>
  {
  public:
    request_handler_impl(Session &session, boost::beast::http::request<Body, Fields> &&req) : request_handler<Session>(session), req(std::move(req)) {}
    virtual ~request_handler_impl() = default;

  private:
    void handle_request() override { request_handler<Session>::handle_req(std::move(req)); }

  private:
    boost::beast::http::request<Body, Fields> req;
  };

  /**
   * @brief The server class.
   */
  class server
  {
    friend class request_handler<http_session>;
    friend class request_handler<ssl_http_session>;
    friend class http_session;
    friend class websocket_session;
    friend class ssl_http_session;
    friend class ssl_websocket_session;

  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080, std::size_t concurrency_hint = std::thread::hardware_concurrency());

    /**
     * @brief Start the server.
     */
    void start();
    /**
     * @brief Stop the server.
     */
    void stop();

    void set_ssl_context(const std::string &certificate_chain_file, const std::string &private_key_file, const std::string &dh_file);

  private:
    void on_accept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket);

    template <class Session, class Body, class Fields>
    void handle_request(Session &session, boost::beast::http::request<Body, Fields> &&req)
    {
    }

  private:
    boost::asio::io_context ioc;                                      // The io_context is required for all I/O
    std::vector<std::thread> threads;                                 // The thread pool
    boost::asio::signal_set signals;                                  // The signal_set is used to register for process termination notifications
    boost::asio::ip::tcp::endpoint endpoint;                          // The endpoint for the server
    boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12}; // The SSL context is required, and holds certificates
    boost::asio::ip::tcp::acceptor acceptor;                          // The acceptor receives incoming connections
    std::vector<std::pair<std::regex, ws_handler>> ws_routes;
    std::vector<std::pair<std::regex, ssl_ws_handler>> ssl_ws_routes;
  };
} // namespace network
