#pragma once

#include "session.hpp"
#include "ws_session.hpp"
#include "route.hpp"

namespace network
{
  class middleware;

  class server
  {
    friend class session;
    friend class ws_session;

  public:
    server(std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT, std::size_t concurrency_hint = std::thread::hardware_concurrency());
    ~server();

    /**
     * @brief Start the server.
     */
    void start();

    /**
     * @brief Stop the server.
     */
    void stop();

    template <typename Tp, typename... Args>
    void add_middleware(Args &&...args)
    {
      static_assert(std::is_base_of<middleware, Tp>::value, "Middleware must inherit from network::middleware");
      auto m = std::make_unique<Tp>(std::forward<Args>(args)...);
      middlewares.push_back(std::move(m));
    }

    /**
     * Adds a route to the server.
     *
     * @param v The HTTP verb associated with the route.
     * @param path The path of the route.
     * @param handler The handler function that will be called when the route is requested.
     */
    void add_route(verb v, std::string_view path, std::function<utils::u_ptr<response>(request &)> &&handler) noexcept;

    /**
     * @brief Retrieves the collection of routes registered on the server.
     *
     * This function provides access to the internal mapping of HTTP verbs
     * to their corresponding routes. The returned map associates each HTTP
     * verb with a vector of routes that are handled by the server.
     *
     * @return A constant reference to a map where the keys are HTTP verbs
     *         (of type `verb`) and the values are vectors of routes (of type `route`).
     *         The returned reference is guaranteed to be valid as long as the
     *         server object exists.
     */
    [[nodiscard]] const std::map<verb, std::vector<route>> &get_routes() const noexcept { return routes; }

    /**
     * Adds a WebSocket route to the server.
     *
     * This function adds a WebSocket route to the server, allowing clients to establish WebSocket connections
     * to the specified path.
     *
     * @param path The path of the WebSocket route.
     * @return A reference to the `ws_handler` associated with the added route.
     */
    ws_handler &add_ws_route(std::string_view path) noexcept { return ws_routes[path.data()]; }

    /**
     * @brief Retrieves the collection of WebSocket routes registered on the server.
     *
     * This function provides access to the internal mapping of WebSocket routes.
     * The returned map associates each WebSocket route path with its corresponding
     * handler function.
     *
     * @return A constant reference to a map where the keys are WebSocket route paths
     *         (of type `std::string`) and the values are `ws_handler` objects that
     *         handle the WebSocket connections.
     */
    [[nodiscard]] const std::map<std::string, ws_handler> &get_ws_routes() const noexcept { return ws_routes; }

#ifdef ENABLE_SSL
    /**
     * @brief Load the server's certificate and private key.
     *
     * This function loads the server's certificate and private key from the specified files.
     *
     * @param cert_file The path to the certificate file.
     * @param key_file The path to the private key file.
     */
    void load_certificate(std::string_view cert_file, std::string_view key_file);
#endif

  private:
    void do_accept();
    void on_accept(const std::error_code &ec, asio::ip::tcp::socket socket);

    void handle_request(session &s, utils::u_ptr<request> req);

    void on_connect(ws_session &s);
    void on_disconnect(ws_session &s);
    void on_message(ws_session &s, utils::u_ptr<message> msg);
    void on_error(ws_session &s, const std::error_code &ec);

  private:
    bool running = false;                                 // The server is running
    asio::io_context io_ctx;                              // The io_context is required for all I/O
    asio::signal_set signals;                             // The signal_set is used to handle signals
    std::vector<std::thread> threads;                     // The thread pool
    const asio::ip::tcp::endpoint endpoint;               // The endpoint for the server
    asio::ip::tcp::acceptor acceptor;                     // The acceptor for the server
    std::map<verb, std::vector<route>> routes;            // The routes of the server
    std::map<std::string, ws_handler> ws_routes;          // The WebSocket routes of the server
    std::vector<std::unique_ptr<middleware>> middlewares; // The middlewares of the server
#ifdef ENABLE_SSL
    asio::ssl::context ctx{asio::ssl::context::TLS_VERSION}; // The SSL context is required, and holds certificates
#endif
  };

  /**
   * Parses a query string and returns a map of key-value pairs.
   *
   * @param query The query string to be parsed.
   * @return A map containing the key-value pairs extracted from the query string.
   */
  inline std::map<std::string, std::string> parse_query(std::string_view query)
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

  /**
   * @brief Decodes a URL-encoded string.
   *
   * This function takes a URL-encoded string and decodes it by converting
   * percent-encoded characters (e.g., "%20") into their corresponding ASCII
   * characters and replacing '+' characters with spaces.
   *
   * @param encoded The URL-encoded string to decode.
   * @return A decoded string with all percent-encoded characters and '+'
   *         characters replaced appropriately.
   *
   * @note The function assumes that the input string is properly URL-encoded.
   *       If the input contains invalid percent-encoded sequences, the behavior
   *       is undefined.
   */
  inline std::string decode(const std::string &encoded)
  {
    std::ostringstream decoded;
    size_t i = 0;
    while (i < encoded.length())
      if (encoded[i] == '%' && i + 2 < encoded.length())
      {
        std::string hex = encoded.substr(i + 1, 2);
        char decodedChar = static_cast<char>(std::stoi(hex, nullptr, 16));
        decoded << decodedChar;
        i += 3; // Skip '%xx'
      }
      else if (encoded[i] == '+')
      {
        decoded << ' '; // '+' is space in URL encoding
        i++;
      }
      else
      {
        decoded << encoded[i];
        i++;
      }
    return decoded.str();
  }
} // namespace network
