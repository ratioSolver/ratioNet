#pragma once

#include <regex>
#include "session.hpp"
#include "ws_session.hpp"

namespace network
{
  class server
  {
    friend class session;
    friend class ws_session;

  public:
    server(const std::string &address = SERVER_HOST, unsigned short port = SERVER_PORT, std::size_t concurrency_hint = std::thread::hardware_concurrency());
    ~server();

    /**
     * @brief Start the server.
     */
    void start();

    /**
     * @brief Stop the server.
     */
    void stop();

    /**
     * Adds a route to the server.
     *
     * @param v The HTTP verb associated with the route.
     * @param path The path of the route.
     * @param handler The handler function that will be called when the route is requested.
     */
    void add_route(verb v, const std::string &path, std::function<std::unique_ptr<response>(request &)> &&handler) noexcept { routes[v].emplace_back(std::regex(path), std::move(handler)); }

    /**
     * Adds a WebSocket route to the server.
     *
     * This function adds a WebSocket route to the server, allowing clients to establish WebSocket connections
     * to the specified path.
     *
     * @param path The path of the WebSocket route.
     * @return A reference to the `ws_handler` associated with the added route.
     */
    ws_handler &add_ws_route(const std::string &path) noexcept { return ws_routes[path]; }

  private:
    void do_accept();
    void on_accept(const boost::system::error_code &ec, boost::asio::ip::tcp::socket socket);

    void handle_request(session &s, std::unique_ptr<request> req);
    void handle_message(ws_session &s, std::unique_ptr<message> msg);

  private:
    bool running = false;                                                                                           // The server is running
    boost::asio::io_context io_ctx;                                                                                 // The io_context is required for all I/O
    std::vector<std::thread> threads;                                                                               // The thread pool
    boost::asio::ip::tcp::endpoint endpoint;                                                                        // The endpoint for the server
    boost::asio::ip::tcp::acceptor acceptor;                                                                        // The acceptor for the server
    std::map<verb, std::vector<std::pair<std::regex, std::function<std::unique_ptr<response>(request &)>>>> routes; // The routes of the server
    std::map<std::string, ws_handler> ws_routes;                                                                    // The WebSocket routes of the server
  };
} // namespace network
