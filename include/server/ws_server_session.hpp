#pragma once

#include "message.hpp"
#include <asio.hpp>
#ifdef ENABLE_SSL
#include <asio/ssl.hpp>
#endif
#include <queue>

namespace network
{
  class server_base;

  class ws_server_session_base : public std::enable_shared_from_this<ws_server_session_base>
  {
    friend class server_base;

  public:
    /**
     * @brief Constructs a WebSocket server session base.
     *
     * This constructor initializes the WebSocket session with the provided server base and executor.
     *
     * @param server The server base associated with this WebSocket session.
     * @param path The path for the WebSocket session.
     * @param executor The executor to use for asynchronous operations.
     */
    ws_server_session_base(server_base &server, std::string_view path, asio::any_io_executor executor);
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
     * Sends a message over the WebSocket session.
     *
     * @param payload The payload to be sent.
     */
    void send(std::string_view payload) { send(std::make_shared<std::string>(payload)); }

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

    void on_read(const asio::error_code &ec, std::size_t bytes_transferred);
    void on_message(const asio::error_code &ec, std::size_t bytes_transferred);
    void on_write(const asio::error_code &ec, std::size_t bytes_transferred);

  private:
    server_base &server;                                    // Reference to the server base associated with this WebSocket session
    std::string path;                                       // The path for the WebSocket session
    asio::any_io_executor &executor;                        // The executor used for asynchronous operations
    std::queue<std::unique_ptr<message>> incoming_messages; // Queue to hold incoming WebSocket messages
    std::queue<std::unique_ptr<message>> outgoing_messages; // Queue to hold outgoing WebSocket messages
  };

  class ws_server_session : public ws_server_session_base
  {
  public:
    ws_server_session(server_base &srv, std::string_view path, asio::ip::tcp::socket &&socket);

  private:
    void read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) override;
    void write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) override;

  private:
    asio::ip::tcp::socket socket; // The socket used to communicate with the client.
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
    wss_server_session(server_base &srv, std::string_view path, asio::ssl::stream<asio::ip::tcp::socket> &&socket);

  private:
    void read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) override;
    void write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) override;

    void on_read(const asio::error_code &ec, std::size_t bytes_transferred);
    void on_message(const asio::error_code &ec, std::size_t bytes_transferred);
    void on_write(const asio::error_code &ec, std::size_t bytes_transferred);

  private:
    asio::ssl::stream<asio::ip::tcp::socket> socket; // The SSL socket used to communicate with the client.
  };
} // namespace network
