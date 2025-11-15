#pragma once

#include "message.hpp"
#ifdef RATIONET_SSL
#include <asio/ssl.hpp>
#endif
#include <queue>

namespace network
{
  class async_client_base;

  class ws_client_session_base : public std::enable_shared_from_this<ws_client_session_base>
  {
  public:
    /**
     * @brief Constructs a WebSocket client base.
     *
     * This constructor initializes the WebSocket client with the provided async client base, host, port, and target URL.
     *
     * @param client The async client base associated with this WebSocket client.
     * @param host The host name of the server.
     * @param port The port number of the server.
     * @param target The target URL or path.
     */
    ws_client_session_base(async_client_base &client, std::string_view host, unsigned short port, std::string_view target, asio::any_io_executor executor);
    /**
     * @brief Destroys the WebSocket client base.
     *
     * This destructor cleans up resources associated with the WebSocket client.
     */
    virtual ~ws_client_session_base();

    void set_on_open(std::function<void()> handler) { on_open_handler = handler; }
    void set_on_message(std::function<void(message &)> handler) { on_message_handler = handler; }
    void set_on_close(std::function<void()> handler) { on_close_handler = handler; }
    void set_on_error(std::function<void(const std::error_code &)> handler) { on_error_handler = handler; }

    void enqueue(std::unique_ptr<message> msg);

    void send(std::shared_ptr<std::string> payload) { enqueue(std::make_unique<message>(payload)); }

    void send(std::string_view payload) { send(std::make_shared<std::string>(payload)); }

    void pong() { enqueue(std::make_unique<message>(0x8A)); }

    void ping() { enqueue(std::make_unique<message>(0x89)); }

    void close() { enqueue(std::make_unique<message>(0x88)); }

    void connect();

    virtual bool is_connected() const = 0;

    virtual void disconnect() = 0;

  private:
    /**
     * @brief Checks if the session is currently connecting to the server.
     *
     * This function returns true if the session is in the process of connecting,
     * false otherwise.
     *
     * @return True if connecting, false otherwise.
     */
    virtual bool is_connecting() const = 0;

    virtual void connect(asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, std::function<void(const asio::error_code &, const asio::ip::tcp::endpoint &)> callback) = 0;

    virtual void read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) = 0;
    virtual void read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) = 0;
    virtual void write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) = 0;

    void on_connect(const asio::error_code &ec, const asio::ip::tcp::endpoint &endpoint);

    void on_read(const asio::error_code &ec, std::size_t bytes_transferred);
    void on_message(const asio::error_code &ec, std::size_t bytes_transferred);
    void on_write(const asio::error_code &ec, std::size_t bytes_transferred);

  protected:
    async_client_base &client;      // Reference to the async client base associated with this WebSocket client.
    const std::string host;         // The host name of the server.
    const unsigned short port;      // The port number of the server.
    const std::string target;       // The target URL or path.
    asio::any_io_executor executor; // The executor used for asynchronous operations
  private:
    asio::ip::tcp::resolver resolver;                              // The resolver used to resolve host names.
    asio::ip::basic_resolver_results<asio::ip::tcp> endpoints;     // The resolved endpoints for the server.
    std::function<void()> on_open_handler;                         // The handler for the open event.
    std::function<void(message &)> on_message_handler;             // The handler for the message event.
    std::function<void()> on_close_handler;                        // The handler for the close event.
    std::function<void(const std::error_code &)> on_error_handler; // The handler for the error event.
    asio::streambuf buffer;                                        // Buffer for reading data
    std::unique_ptr<message> current_message;                      // Pointer to the current message being processed
    std::queue<std::unique_ptr<message>> outgoing_messages;        // Queue to hold outgoing WebSocket messages
  };

  class ws_client_session : public ws_client_session_base
  {
  public:
    /**
     * @brief Constructs a WebSocket client session.
     *
     * This constructor initializes the WebSocket client with the provided async client base, host, port, and target URL.
     *
     * @param client The async client base associated with this WebSocket client.
     * @param host The host name of the server.
     * @param port The port number of the server.
     * @param target The target URL or path.
     * @param socket The socket used to communicate with the server.
     */
    ws_client_session(async_client_base &client, std::string_view host, unsigned short port, std::string_view target, asio::ip::tcp::socket &&socket);
    /**
     * @brief Destroys the WebSocket client session.
     *
     * This destructor cleans up resources associated with the WebSocket client session.
     */
    ~ws_client_session() override;

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

#ifdef RATIONET_SSL
  class wss_client_session : public ws_client_session_base
  {
  public:
    /**
     * @brief Constructs a secure WebSocket client session.
     *
     * This constructor initializes the WebSocket client with SSL support.
     *
     * @param client The async client base associated with this WebSocket client.
     * @param host The host name of the server.
     * @param port The port number of the server.
     * @param target The target URL or path.
     * @param socket The SSL socket used to communicate with the server.
     */
    wss_client_session(async_client_base &client, std::string_view host, unsigned short port, std::string_view target, asio::ssl::stream<asio::ip::tcp::socket> &&socket);
    /**
     * @brief Destroys the WebSocket client session with SSL support.
     *
     * This destructor cleans up resources associated with the WebSocket client session with SSL support.
     */
    ~wss_client_session() override;

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
