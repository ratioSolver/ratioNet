#pragma once

#include <thread>
#include <regex>
#include "http_session.hpp"

namespace network
{
  class websocket_session
  {
  };

  class http_handler
  {
  public:
    virtual ~http_handler() = default;
  };

  class server
  {
  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080, std::size_t concurrency_hint = std::thread::hardware_concurrency());

    void start();

    void stop();

  private:
    virtual void do_accept() = 0;

  private:
    boost::optional<http_handler &> get_http_handler(boost::beast::http::verb method, const std::string &target);
#ifdef USE_SSL
    boost::optional<http_handler &> get_https_handler(boost::beast::http::verb method, const std::string &target);
#endif

  protected:
    static std::map<std::string, std::string> parse_query(const std::string &query);

  protected:
    boost::asio::io_context io_ctx;          // The io_context is required for all I/O
    std::vector<std::thread> threads;        // The thread pool
    boost::asio::signal_set signals;         // The signal_set is used to register for process termination notifications
    boost::asio::ip::tcp::endpoint endpoint; // The endpoint for the server
    boost::asio::ip::tcp::acceptor acceptor; // The acceptor receives incoming connections
    std::unordered_map<boost::beast::http::verb, std::vector<std::pair<std::regex, std::unique_ptr<http_handler>>>> http_routes;
#ifdef USE_SSL
    boost::asio::ssl::context ctx{boost::asio::ssl::context::TLS_VERSION}; // The SSL context is required, and holds certificates
    std::unordered_map<boost::beast::http::verb, std::vector<std::pair<std::regex, std::unique_ptr<http_handler>>>> https_routes;
#endif
  };
} // namespace network
