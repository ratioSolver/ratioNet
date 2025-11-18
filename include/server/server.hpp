#pragma once

#include "verb.hpp"
#include "route.hpp"
#include "ws_handler.hpp"
#include "server_session.hpp"
#include "ws_server_session.hpp"
#include "middleware.hpp"
#include <asio.hpp>
#ifdef RATIONET_SSL
#include <asio/ssl.hpp>
#endif
#include <typeindex>

namespace network
{
  class server_session_base;
  class ws_server_session_base;

  [[nodiscard]] inline std::string default_server_host() noexcept
  {
    const char *host = std::getenv("SERVER_HOST");
    if (host)
      return std::string(host);
    return "0.0.0.0";
  }

  [[nodiscard]] inline unsigned short default_server_port() noexcept
  {
    const char *port = std::getenv("SERVER_PORT");
    if (port)
      return static_cast<unsigned short>(std::stoi(port));
    return 8080;
  }

  class server_base
  {
    friend class server_session_base;
    friend class ws_server_session_base;

  public:
    /**
     * @brief Constructs a server_base instance with the specified host, port, and concurrency hint.
     *
     * @param host The host address to bind the server to. Defaults to "0.0.0.0".
     * @param port The port number to listen on. Defaults to 8080.
     * @param concurrency_hint The suggested number of threads for handling server operations.
     *        Defaults to the number of hardware threads available.
     */
    server_base(std::string_view host = default_server_host(), unsigned short port = default_server_port(), std::size_t concurrency_hint = std::thread::hardware_concurrency());
    /**
     * @brief Destroys the server_base instance.
     *
     * This destructor stops the server and cleans up resources.
     */
    virtual ~server_base();

    /**
     * @brief Starts the server.
     *
     * This function initializes the server, binds it to the specified host and port,
     * and begins listening for incoming connections. It also starts the thread pool
     * to handle incoming requests.
     */
    void start();

    /**
     * @brief Stops the server.
     *
     * This function stops the server, closes all connections, and joins all threads
     * in the thread pool. It should be called to gracefully shut down the server.
     */
    void stop();

    /**
     * Adds a route to the server.
     *
     * @param v The HTTP verb associated with the route.
     * @param path The path of the route.
     * @param handler The handler function that will be called when the route is requested.
     */
    void add_route(verb v, std::string_view path, std::function<std::unique_ptr<response>(request &)> &&handler) noexcept;

    /**
     * @brief Retrieves the collection of routes registered on the server.
     *
     * This function provides access to the internal mapping of HTTP verbs
     * to their corresponding routes. The returned map associates each HTTP
     * verb with a vector of routes that are handled by the server.
     *
     * @return A constant reference to a map where the keys are HTTP verbs
     *         (of type `verb`) and the values are vectors of routes (of type `route`).
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

    /**
     * @brief Adds a middleware to the server.
     *
     * This function constructs a middleware object of type Tp using the provided arguments
     * and adds it to the list of middlewares. The middleware type Tp must inherit from
     * network::middleware.
     *
     * @tparam Tp The type of the middleware to add. Must derive from network::middleware.
     * @tparam Args The types of the arguments to forward to the middleware's constructor.
     * @param args Arguments to forward to the middleware's constructor.
     */
    template <typename Tp, typename... Args>
    Tp &add_middleware(Args &&...args)
    {
      static_assert(std::is_base_of<middleware, Tp>::value, "Middleware must inherit from network::middleware");
      if (auto it = middlewares.find(typeid(Tp)); it == middlewares.end())
      {
        auto m = std::make_unique<Tp>(std::forward<Args>(args)...);
        auto &ref = *m;
        middlewares.emplace(typeid(Tp), std::move(m));
        return ref;
      }
      else
        throw std::runtime_error("Module already exists");
    }

    /**
     * @brief Retrieves a middleware of the specified type.
     *
     * This function returns a reference to the middleware of type Tp if it exists.
     * The middleware type Tp must inherit from network::middleware.
     *
     * @tparam Tp The type of the middleware to retrieve. Must derive from network::middleware.
     * @return A reference to the middleware of type Tp.
     * @throws std::runtime_error if the middleware of type Tp is not found.
     */
    template <typename Tp>
    [[nodiscard]] Tp &get_middleware() const
    {
      static_assert(std::is_base_of<middleware, Tp>::value, "Middleware must inherit from network::middleware");
      if (auto it = middlewares.find(typeid(Tp)); it != middlewares.end())
        return *static_cast<Tp *>(it->second.get());
      throw std::runtime_error("Middleware not found");
    }

  protected:
    void do_accept();

  private:
    virtual void on_accept(const std::error_code &ec, asio::ip::tcp::socket socket) = 0;

    void handle_request(server_session_base &s, request &req);

    void on_connect(ws_server_session_base &s);
    void on_disconnect(ws_server_session_base &s);
    void on_message(ws_server_session_base &s, const message &msg);
    void on_error(ws_server_session_base &s, const std::error_code &ec);

  private:
    asio::io_context io_ctx;                                            // The io_context is required for all I/O
    asio::signal_set signals;                                           // The signal_set is used to handle signals
    std::vector<std::thread> threads;                                   // The thread pool
    const asio::ip::tcp::endpoint endpoint;                             // The endpoint for the server
    asio::ip::tcp::acceptor acceptor;                                   // The acceptor for the server
    std::map<verb, std::vector<route>> routes;                          // The routes of the server
    std::map<std::string, ws_handler> ws_routes;                        // The WebSocket routes of the server
    std::map<std::type_index, std::unique_ptr<middleware>> middlewares; // The middlewares of the server
  };

  class server : public server_base
  {
  public:
    /**
     * @brief Constructs a server instance with the specified host, port, and concurrency hint.
     *
     * @param host The hostname or IP address to bind the server to. Defaults to SERVER_HOST.
     * @param port The port number to listen on. Defaults to SERVER_PORT.
     * @param concurrency_hint The suggested number of threads for handling server operations.
     *        Defaults to the number of hardware threads available.
     */
    server(std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT, std::size_t concurrency_hint = std::thread::hardware_concurrency());

  private:
    /**
     * @brief Handles the accept operation for incoming connections.
     *
     * This function is called when a new connection is accepted.
     *
     * @param ec The error code indicating the result of the accept operation.
     * @param socket The accepted socket.
     */
    void on_accept(const std::error_code &ec, asio::ip::tcp::socket socket) override;
  };

#ifdef RATIONET_SSL
  class ssl_server : public server_base
  {
  public:
    /**
     * @brief Constructs an SSL server instance with the specified host, port, and concurrency hint.
     *
     * @param host The hostname or IP address to bind the server to. Defaults to SERVER_HOST.
     * @param port The port number to listen on. Defaults to SERVER_PORT.
     * @param concurrency_hint The suggested number of threads for handling server operations.
     *        Defaults to the number of hardware threads available.
     */
    ssl_server(std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT, std::size_t concurrency_hint = std::thread::hardware_concurrency());

    /**
     * @brief Load the server's certificate and private key.
     *
     * This function loads the server's certificate and private key from the specified files.
     *
     * @param cert_file The path to the certificate file.
     * @param key_file The path to the private key file.
     */
    void load_certificate(std::string_view cert_file, std::string_view key_file);

  private:
    /**
     * @brief Handles the accept operation for incoming SSL connections.
     *
     * This function is called when a new SSL connection is accepted.
     *
     * @param ec The error code indicating the result of the accept operation.
     * @param socket The accepted SSL socket.
     */
    void on_accept(const std::error_code &ec, asio::ip::tcp::socket socket) override;

  private:
    asio::ssl::context ssl_ctx; // The SSL context used for secure connections
  };
#endif

  /**
   * Parses a query string and returns a map of key-value pairs.
   *
   * @param query The query string to be parsed.
   * @return A map containing the key-value pairs extracted from the query string.
   */
  [[nodiscard]] inline std::map<std::string, std::string> parse_query(std::string_view query)
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
  [[nodiscard]] inline std::string decode(const std::string &encoded)
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

  /**
   * @brief Splits a string into a vector of substrings based on a delimiter.
   *
   * This function takes a string and a delimiter character, and splits the string
   * into substrings wherever the delimiter is found. The resulting substrings are
   * returned as a vector of strings.
   *
   * @param str The input string to be split.
   * @param delimiter The character used to delimit the substrings.
   * @return A vector containing the substrings obtained by splitting the input string.
   */
  [[nodiscard]] inline std::vector<std::string> split_string(std::string_view str, char delimiter)
  {
    std::vector<std::string> result;
    std::string::size_type start = 0;
    std::string::size_type end = str.find(delimiter);

    while (end != std::string::npos)
    {
      result.emplace_back(str.substr(start, end - start));
      start = end + 1;
      end = str.find(delimiter, start);
    }

    result.emplace_back(str.substr(start));
    return result;
  }
} // namespace network
