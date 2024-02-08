#pragma once

#include <thread>
#include <regex>
#include <map>
#include <unordered_map>
#include "http_handler.hpp"
#include "websocket_handler.hpp"

namespace network
{
  class server
  {
    friend class http_session;
#ifdef USE_SSL
    friend class session_detector;
#endif

  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080, std::size_t concurrency_hint = std::thread::hardware_concurrency());

    void start();

    void stop();

    websocket_handler &ws(const std::string &target);

#ifdef USE_SSL
    void set_ssl_context(const std::string &cert_chain_file, const std::string &private_key_file, const std::string &tmp_dh_file);
    websocket_handler &wss(const std::string &target);
#endif

    void set_log_handler(std::function<void(const std::string &)> handler) { log_handler = handler; }
    void set_error_handler(std::function<void(const std::string &)> handler) { error_handler = handler; }

  private:
    virtual void do_accept() = 0;

  private:
    boost::optional<http_handler &> get_http_handler(boost::beast::http::verb method, const std::string &target);
    boost::optional<websocket_handler &> get_ws_handler(const std::string &target);
#ifdef USE_SSL
    boost::optional<http_handler &> get_https_handler(boost::beast::http::verb method, const std::string &target);
    boost::optional<websocket_handler &> get_wss_handler(const std::string &target);
#endif

  protected:
    static std::map<std::string, std::string> parse_query(const std::string &query);

  protected:
    std::function<void(const std::string &)> log_handler = [](const std::string &) {};
    std::function<void(const std::string &)> error_handler = [](const std::string &) {};
    boost::asio::io_context io_ctx;          // The io_context is required for all I/O
    std::vector<std::thread> threads;        // The thread pool
    boost::asio::signal_set signals;         // The signal_set is used to register for process termination notifications
    boost::asio::ip::tcp::endpoint endpoint; // The endpoint for the server
    boost::asio::ip::tcp::acceptor acceptor; // The acceptor receives incoming connections
    std::unordered_map<boost::beast::http::verb, std::vector<std::pair<std::regex, std::unique_ptr<http_handler>>>> http_routes;
    std::vector<std::pair<std::regex, std::unique_ptr<websocket_handler>>> ws_routes;
#ifdef USE_SSL
    boost::asio::ssl::context ctx{boost::asio::ssl::context::TLS_VERSION}; // The SSL context is required, and holds certificates
    std::unordered_map<boost::beast::http::verb, std::vector<std::pair<std::regex, std::unique_ptr<http_handler>>>> https_routes;
    std::vector<std::pair<std::regex, std::unique_ptr<websocket_handler>>> wss_routes;
#endif
  };
} // namespace network
