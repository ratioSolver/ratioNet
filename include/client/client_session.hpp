#pragma once

#include "request.hpp"
#include "response.hpp"
#include <asio.hpp>
#ifdef ENABLE_SSL
#include <asio/ssl.hpp>
#endif
#include <queue>

namespace network
{
  class async_client_base;

  class client_session_base : public std::enable_shared_from_this<client_session_base>
  {
  public:
    /**
     * @brief Constructs a client_session_base instance.
     *
     * This constructor initializes the session with the provided client base and host/port.
     *
     * @param client The client base associated with this session.
     * @param host The host name of the server (default is SERVER_HOST).
     * @param port The port number of the server (default is SERVER_PORT).
     */
    explicit client_session_base(async_client_base &client, std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT);

    /**
     * @brief Destroys the client_session instance.
     */
    virtual ~client_session_base();

    /**
     * @brief Sends a request asynchronously and invokes a callback upon receiving the response.
     *
     * This function takes ownership of the provided request object and sends it to the server.
     * Once a response is received, the specified callback function is called with the response.
     *
     * @param req A unique pointer to the request object to be sent.
     * @param cb A callback function that will be invoked with the received response.
     */
    void send(std::unique_ptr<request> req, std::function<void(const response &)> &&cb);

    /**
     * @brief Sends a GET request asynchronously.
     *
     * This method sends a GET request to the specified target resource on the server.
     *
     * @param target The target resource on the server.
     * @param cb A callback function to be called with the response once it is received.
     * @param hdrs Optional headers to include in the request.
     */
    void get(std::string_view target, std::function<void(const response &)> &&cb, std::multimap<std::string, std::string> &&hdrs = {}) { send(std::make_unique<request>(verb::Get, target, "HTTP/1.1", std::move(hdrs)), std::move(cb)); }

    /**
     * @brief Sends a PUT request with a string body asynchronously.
     *
     * This method sends a POST request to the specified target resource on the server with the provided body.
     *
     * @param target The target resource on the server.
     * @param body The body of the POST request.
     * @param cb A callback function to be called with the response once it is received.
     * @param hdrs Optional headers to include in the request.
     */
    void post(std::string_view target, std::string &&body, std::function<void(const response &)> &&cb, std::multimap<std::string, std::string> &&hdrs = {}) { send(std::make_unique<string_request>(verb::Post, target, "HTTP/1.1", std::move(hdrs), std::move(body)), std::move(cb)); }

    /**
     * @brief Sends a POST request with a JSON body asynchronously.
     *
     * This method sends a POST request to the specified target resource on the server with the provided JSON body.
     *
     * @param target The target resource on the server.
     * @param body The JSON body of the POST request.
     * @param cb A callback function to be called with the response once it is received.
     * @param hdrs Optional headers to include in the request.
     */
    void post(std::string_view target, json::json &&body, std::function<void(const response &)> &&cb, std::multimap<std::string, std::string> &&hdrs = {}) { send(std::make_unique<json_request>(verb::Post, target, "HTTP/1.1", std::move(hdrs), std::move(body)), std::move(cb)); }

    /**
     * @brief Sends a PUT request with a string body asynchronously.
     *
     * This method sends a PUT request to the specified target resource on the server with the provided body.
     *
     * @param target The target resource on the server.
     * @param body The body of the PUT request.
     * @param cb A callback function to be called with the response once it is received.
     * @param hdrs Optional headers to include in the request.
     */
    void put(std::string_view target, std::string &&body, std::function<void(const response &)> &&cb, std::multimap<std::string, std::string> &&hdrs = {}) { send(std::make_unique<string_request>(verb::Put, target, "HTTP/1.1", std::move(hdrs), std::move(body)), std::move(cb)); }

    /**
     * @brief Sends a PUT request with a JSON body asynchronously.
     *
     * This method sends a PUT request to the specified target resource on the server with the provided JSON body.
     *
     * @param target The target resource on the server.
     * @param body The JSON body of the PUT request.
     * @param cb A callback function to be called with the response once it is received.
     * @param hdrs Optional headers to include in the request.
     */
    void put(std::string_view target, json::json &&body, std::function<void(const response &)> &&cb, std::multimap<std::string, std::string> &&hdrs = {}) { send(std::make_unique<json_request>(verb::Put, target, "HTTP/1.1", std::move(hdrs), std::move(body)), std::move(cb)); }

    /**
     * @brief Sends a PATCH request with a string body asynchronously.
     *
     * This method sends a PATCH request to the specified target resource on the server with the provided body.
     *
     * @param target The target resource on the server.
     * @param body The body of the PATCH request.
     * @param cb A callback function to be called with the response once it is received.
     * @param hdrs Optional headers to include in the request.
     */
    void patch(std::string_view target, std::string &&body, std::function<void(const response &)> &&cb, std::multimap<std::string, std::string> &&hdrs = {}) { send(std::make_unique<string_request>(verb::Patch, target, "HTTP/1.1", std::move(hdrs), std::move(body)), std::move(cb)); }

    /**
     * @brief Sends a PATCH request with a JSON body asynchronously.
     *
     * This method sends a PATCH request to the specified target resource on the server with the provided JSON body.
     *
     * @param target The target resource on the server.
     * @param body The JSON body of the PATCH request.
     * @param cb A callback function to be called with the response once it is received.
     * @param hdrs Optional headers to include in the request.
     */
    void patch(std::string_view target, json::json &&body, std::function<void(const response &)> &&cb, std::multimap<std::string, std::string> &&hdrs = {}) { send(std::make_unique<json_request>(verb::Patch, target, "HTTP/1.1", std::move(hdrs), std::move(body)), std::move(cb)); }

    /**
     * @brief Sends a DELETE request asynchronously.
     *
     * This method sends a DELETE request to the specified target resource on the server.
     *
     * @param target The target resource on the server.
     * @param cb A callback function to be called with the response once it is received.
     * @param hdrs Optional headers to include in the request.
     */
    void del(std::string_view target, std::function<void(const response &)> &&cb, std::multimap<std::string, std::string> &&hdrs = {}) { send(std::make_unique<request>(verb::Delete, target, "HTTP/1.1", std::move(hdrs)), std::move(cb)); }

    /**
     * @brief Establishes a connection to the server.
     *
     * This function initiates the process of connecting the client session
     * to the designated server. It should be called before attempting any
     * communication or data exchange with the server.
     *
     * @throws std::runtime_error if the connection fails.
     */
    void connect();

    /**
     * @brief Checks if the session is currently connected to the server.
     *
     * This function returns true if the session is connected, false otherwise.
     *
     * @return True if connected, false otherwise.
     */
    virtual bool is_connected() const = 0;

    /**
     * @brief Disconnects from the server.
     *
     * This function closes the connection to the server.
     */
    virtual void disconnect() = 0;

  private:
    virtual void connect(asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, std::function<void(const asio::error_code &, const asio::ip::tcp::endpoint &)> callback) = 0;

    /**
     * @brief Checks if the session is currently connecting to the server.
     *
     * This function returns true if the session is in the process of connecting,
     * false otherwise.
     *
     * @return True if connecting, false otherwise.
     */
    virtual bool is_connecting() const = 0;

    virtual void read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) = 0;
    virtual void read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) = 0;
    virtual void write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) = 0;

    void on_connect(const asio::error_code &ec, const asio::ip::tcp::endpoint &endpoint);
    void on_write(const asio::error_code &ec, std::size_t bytes_transferred);
    void on_read_headers(const asio::error_code &ec, std::size_t bytes_transferred);
    void on_read_body(const asio::error_code &ec, std::size_t bytes_transferred);
    void read_chunk();

  protected:
    async_client_base &client; // Reference to the client base associated with this session
    const std::string host;    // The host name of the server
    const unsigned short port; // The port number of the server
  private:
    asio::ip::tcp::resolver resolver;                          // The resolver used to resolve host names.
    asio::ip::basic_resolver_results<asio::ip::tcp> endpoints; // The resolved endpoints for the server.
  private:
    asio::strand<asio::io_context::executor_type> strand;                                                 // Strand to ensure thread-safe operations within the session
    asio::streambuf buffer;                                                                               // Buffer for reading data
    std::queue<std::pair<std::unique_ptr<request>, std::function<void(const response &)>>> request_queue; // Queue to hold outgoing requests
    std::unique_ptr<response> current_response = std::make_unique<response>();                            // Pointer to the current response being processed
    std::queue<std::function<void(const response &)>> callback_queue;                                     // Queue to hold callbacks for responses
  };

  /**
   * @brief Represents a session in the client context.
   *
   * This class is used to manage the state and operations of a session within the client.
   * It inherits from client_session_base to provide common functionality for client sessions.
   */
  class client_session : public client_session_base
  {
  public:
    /**
     * @brief Constructs a client_session instance.
     *
     * This constructor initializes the session with the provided client base and socket.
     *
     * @param client The client base associated with this session.
     * @param socket The socket used to communicate with the server.
     */
    client_session(async_client_base &client, std::string_view host, unsigned short port, asio::ip::tcp::socket &&socket);
    ~client_session() override;

    bool is_connected() const override;
    void disconnect() override;

  private:
    bool is_connecting() const override { return connecting; } // Check if the session is currently connecting
    void connect(asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, std::function<void(const asio::error_code &, const asio::ip::tcp::endpoint &)> callback) override;

    void read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) override;
    void read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) override;
    void write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) override;

  private:
    asio::ip::tcp::socket socket; // The socket used to communicate with the server.
    bool connecting{false};       // Flag to track if a connection attempt is in progress
  };

#ifdef ENABLE_SSL
  /**
   * @brief Represents a secure session in the client context.
   *
   * This class is used to manage the state and operations of a secure session within the client.
   * It inherits from client_session_base to provide common functionality for secure client sessions.
   */
  class ssl_client_session : public client_session_base
  {
  public:
    /**
     * @brief Constructs an ssl_client_session instance.
     *
     * This constructor initializes the session with the provided client base and SSL socket.
     *
     * @param client The client base associated with this session.
     * @param socket The SSL socket used to communicate with the server.
     */
    ssl_client_session(async_client_base &client, std::string_view host, unsigned short port, asio::ssl::stream<asio::ip::tcp::socket> &&socket);
    ~ssl_client_session() override;

    bool is_connected() const override;
    void disconnect() override;

  private:
    bool is_connecting() const override { return connecting; } // Check if the session is currently connecting
    void connect(asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, std::function<void(const asio::error_code &, const asio::ip::tcp::endpoint &)> callback) override;

    void read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) override;
    void read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) override;
    void write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) override;

  private:
    asio::ssl::stream<asio::ip::tcp::socket> socket; // The SSL socket used to communicate with the server.
    bool connecting{false};                          // Flag to track if a connection attempt is in progress
  };
#endif
} // namespace network
