#pragma once

#include "session.hpp"
#include "ws_session.hpp"
#include <regex>
#ifdef ENABLE_AUTH
#include <set>
#endif

namespace network
{
  class server
  {
    friend class session;
    friend class ws_session;

  public:
    server(const std::string &host = SERVER_HOST, unsigned short port = SERVER_PORT, std::size_t concurrency_hint = std::thread::hardware_concurrency());
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

#ifdef ENABLE_SSL
    /**
     * @brief Load the server's certificate and private key.
     *
     * This function loads the server's certificate and private key from the specified files.
     *
     * @param cert_file The path to the certificate file.
     * @param key_file The path to the private key file.
     */
    void load_certificate(const std::string &cert_file, const std::string &key_file)
    {
      ctx.use_certificate_chain_file(cert_file);
      ctx.use_private_key_file(key_file, boost::asio::ssl::context::pem);
    }
#endif

  private:
    void do_accept();
    void on_accept(const boost::system::error_code &ec, boost::asio::ip::tcp::socket socket);

    void handle_request(session &s, std::unique_ptr<request> req);

    void on_connect(ws_session &s);
    void on_disconnect(ws_session &s);
    void on_message(ws_session &s, std::unique_ptr<message> msg);
    void on_error(ws_session &s, const boost::system::error_code &ec);

#ifdef ENABLE_AUTH
    std::unique_ptr<json_response> login(const request &req);

    /**
     * Generates a token for the given username and password.
     *
     * @param username The username for which to generate the token.
     * @param password The password for the given username.
     * @return The generated token as a string.
     */
    virtual std::string generate_token(const std::string &username, const std::string &password) = 0;

    /**
     * @brief Checks if the given request has permission with the specified token.
     *
     * @param req The request to check permission for.
     * @param token The token to use for permission checking.
     * @return True if the request has permission, false otherwise.
     */
    virtual bool has_permission(const request &req, const std::string &token) = 0;
#endif

  private:
    bool running = false;                                                                                           // The server is running
    boost::asio::io_context io_ctx;                                                                                 // The io_context is required for all I/O
    std::vector<std::thread> threads;                                                                               // The thread pool
    boost::asio::ip::tcp::endpoint endpoint;                                                                        // The endpoint for the server
    boost::asio::ip::tcp::acceptor acceptor;                                                                        // The acceptor for the server
    std::map<verb, std::vector<std::pair<std::regex, std::function<std::unique_ptr<response>(request &)>>>> routes; // The routes of the server
    std::map<std::string, ws_handler> ws_routes;                                                                    // The WebSocket routes of the server
#ifdef ENABLE_AUTH
  protected:
    std::set<std::string> open_routes; // The routes that are open to all users
#endif
#ifdef ENABLE_SSL
    boost::asio::ssl::context ctx{boost::asio::ssl::context::TLS_VERSION}; // The SSL context is required, and holds certificates
#endif
  };

  /**
   * Parses a query string and returns a map of key-value pairs.
   *
   * @param query The query string to be parsed.
   * @return A map containing the key-value pairs extracted from the query string.
   */
  inline std::map<std::string, std::string> parse_query(const std::string &query)
  {
    std::map<std::string, std::string> params;

    std::string::size_type pos = 0;
    while (pos < query.size())
    {
      std::string::size_type next = query.find('&', pos);
      std::string::size_type eq = query.find('=', pos);
      if (eq == std::string::npos)
        break;
      if (next == std::string::npos)
        next = query.size();
      params.emplace(query.substr(pos, eq - pos), query.substr(eq + 1, next - eq - 1));
      pos = next + 1;
    }

    return params;
  }
} // namespace network
