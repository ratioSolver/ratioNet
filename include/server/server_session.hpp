#pragma once

#include "request.hpp"
#include "response.hpp"
#include "message.hpp"
#include <asio.hpp>
#ifdef ENABLE_SSL
#include <asio/ssl.hpp>
#endif
#include <queue>

namespace network
{
  class server_base;

  class server_session_base : public std::enable_shared_from_this<server_session_base>
  {
    friend class server_base;

  public:
    /**
     * @brief Constructs a server_session_base instance.
     *
     * This constructor initializes the session with the provided server base.
     *
     * @param server The server base associated with this session.
     */
    explicit server_session_base(server_base &server);

    /**
     * @brief Destroys the server_session_base instance.
     */
    virtual ~server_session_base();

    server_base &get_server() { return server; }
    const server_base &get_server() const { return server; }

    void run();

    /**
     * @brief Enqueues a response for sending.
     *
     * This method adds a response to the session's response queue for later sending.
     *
     * @param res The response to enqueue.
     */
    void enqueue(std::unique_ptr<response> res);

  private:
    void upgrade();

    virtual void read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) = 0;
    virtual void read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) = 0;
    virtual void write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) = 0;

    virtual void on_upgrade(const asio::error_code &ec, std::size_t bytes_transferred) = 0;

    void on_write(const asio::error_code &ec, std::size_t bytes_transferred);
    void on_read_headers(const asio::error_code &ec, std::size_t bytes_transferred);
    void on_read_body(const asio::error_code &ec, std::size_t bytes_transferred);
    void read_chunk(std::string body = "");

  private:
    server_base &server;                                  // Reference to the server base associated with this session
    asio::strand<asio::io_context::executor_type> strand; // Strand to ensure thread-safe operations within the session
    std::queue<std::unique_ptr<request>> request_queue;   // Queue to hold incoming requests
    std::queue<std::unique_ptr<response>> response_queue; // Queue to hold outgoing responses
  };

  class ws_server_session_base : public std::enable_shared_from_this<ws_server_session_base>
  {
  public:
    /**
     * @brief Constructs a WebSocket server session base.
     *
     * This constructor initializes the WebSocket session with the provided server base and executor.
     *
     * @param server The server base associated with this WebSocket session.
     * @param executor The executor to use for asynchronous operations.
     */
    ws_server_session_base(server_base &server, asio::io_context::executor_type executor);
    /**
     * @brief Destroys the WebSocket server session base.
     */
    virtual ~ws_server_session_base();

    /**
     * @brief Starts the WebSocket session.
     *
     * This function initializes the WebSocket session and prepares it for communication.
     */
    void run();

    /**
     * @brief Enqueues a WebSocket message for sending.
     *
     * This method adds a WebSocket message to the session's message queue for later sending.
     *
     * @param msg The WebSocket message to enqueue.
     */
    void enqueue(std::unique_ptr<message> msg);

    /**
     * @brief Sends a message to the client by enqueuing the provided payload.
     *
     * This function wraps the given payload in a `message` object and enqueues it
     * for asynchronous delivery to the connected client.
     *
     * @param payload A shared pointer to the string data to be sent.
     */
    void send(std::shared_ptr<std::string> payload) { enqueue(std::make_unique<message>(payload)); }

    /**
     * @brief Sends a WebSocket Pong frame to the client.
     *
     * This function enqueues a Pong message (opcode 0x8A) to maintain the connection alive
     * or respond to a Ping frame as per the WebSocket protocol.
     */
    void pong() { enqueue(std::make_unique<message>(0x8A)); }
    /**
     * @brief Sends a WebSocket Ping frame to the client.
     *
     * This function enqueues a Ping message (opcode 0x89) to the outgoing message queue,
     * which is used to check the connection's liveness as per the WebSocket protocol.
     */
    void ping() { enqueue(std::make_unique<message>(0x89)); }
    /**
     * @brief Closes the WebSocket connection.
     *
     * This function enqueues a Close message (opcode 0x88) to gracefully close the WebSocket connection.
     */
    void close() { enqueue(std::make_unique<message>(0x88)); }

  private:
    virtual void read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) = 0;
    virtual void write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) = 0;

  private:
    server_base &server;                                    // Reference to the server base associated with this WebSocket session
    asio::strand<asio::io_context::executor_type> strand;   // Strand to ensure thread-safe operations within the WebSocket session
    std::queue<std::unique_ptr<message>> incoming_messages; // Queue to hold incoming WebSocket messages
    std::queue<std::unique_ptr<message>> outgoing_messages; // Queue to hold outgoing WebSocket messages
  };

  /**
   * @brief Represents a session in the server context.
   *
   * This class is used to manage the state and operations of a session within the server.
   * It inherits from server_session_base to provide common functionality for server sessions.
   */
  class server_session : public server_session_base
  {
  public:
    /**
     * @brief Constructs a server_session instance.
     *
     * This constructor initializes the session with the provided server base and socket.
     *
     * @param srv The server base associated with this session.
     * @param socket The socket used to communicate with the client.
     */
    server_session(server_base &srv, asio::ip::tcp::socket &&socket);

  private:
    void on_upgrade(const asio::error_code &ec, std::size_t bytes_transferred) override;

    void read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) override;
    void read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) override;
    void write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) override;

  private:
    asio::ip::tcp::socket socket; // The socket used to communicate with the client.
  };

  class ws_server_session : public ws_server_session_base
  {
  public:
    ws_server_session(server_base &srv, asio::ip::tcp::socket &&socket);

  private:
    void read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) override;
    void write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) override;

    void on_read(const asio::error_code &ec, std::size_t bytes_transferred);
    void on_message(const asio::error_code &ec, std::size_t bytes_transferred);
    void on_write(const asio::error_code &ec, std::size_t bytes_transferred);

  private:
    asio::ip::tcp::socket socket; // The socket used to communicate with the client.
  };

#ifdef ENABLE_SSL
  /**
   * @brief Represents a secure session in the server context.
   *
   * This class is used to manage secure sessions within the server, inheriting from server_session_base.
   */
  class ssl_server_session : public server_session_base
  {
  public:
    /**
     * @brief Constructs a secure_server_session instance.
     *
     * @param srv The server base associated with this session.
     * @param socket The SSL socket used to communicate with the client.
     */
    ssl_server_session(server_base &srv, asio::ssl::stream<asio::ip::tcp::socket> &&socket);

    /**
     * @brief Initiates the SSL handshake.
     *
     * This method is called to perform the SSL handshake with the client.
     */
    void handshake(std::function<void(const std::error_code &)> callback);

  private:
    void on_upgrade(const asio::error_code &ec, std::size_t bytes_transferred) override;

    void read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) override;
    void read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) override;
    void write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) override;

  private:
    asio::ssl::stream<asio::ip::tcp::socket> socket; // The SSL socket used for secure communication.
  };

  class wss_server_session : public ws_server_session_base
  {
  public:
    /**
     * @brief Constructs a secure WebSocket server session.
     *
     * @param srv The server base associated with this session.
     * @param socket The SSL socket used to communicate with the client.
     */
    wss_server_session(server_base &srv, asio::ssl::stream<asio::ip::tcp::socket> &&socket);

  private:
    void read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) override;
    void write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) override;

    void on_read(const asio::error_code &ec, std::size_t bytes_transferred);
    void on_message(const asio::error_code &ec, std::size_t bytes_transferred);
    void on_write(const asio::error_code &ec, std::size_t bytes_transferred);

  private:
    asio::ssl::stream<asio::ip::tcp::socket> socket; // The SSL socket used to communicate with the client.
  };
#endif
} // namespace network
