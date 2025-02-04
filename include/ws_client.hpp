#pragma once

#include "memory.hpp"
#include "message.hpp"
#ifdef ENABLE_SSL
#include <asio/ssl.hpp>
#endif
#include <queue>

namespace network
{
  class ws_client;

  class ws_client_handler
  {
    friend class ws_client;

  public:
    ws_client_handler() = default;

    /**
     * @brief Registers a handler function to be called when the WebSocket session is opened.
     *
     * This function allows to set a custom handler function to be called when the WebSocket session is opened.
     *
     * @param handler The handler function to be called when the WebSocket session is opened.
     */
    ws_client_handler &on_open(std::function<void()> &&handler) noexcept
    {
      on_open_handler = std::move(handler);
      return *this;
    }

    /**
     * @brief Registers a handler function to be called when a message is received.
     *
     * This function allows to set a custom handler function to be called when a message is received by the WebSocket session.
     * The handler function should take a reference to to the received message as its parameters.
     *
     * @param handler The handler function to be called. It takes a reference to to the received message.
     */
    ws_client_handler &on_message(std::function<void(std::string_view)> &&handler) noexcept
    {
      on_message_handler = std::move(handler);
      return *this;
    }

    /**
     * @brief Sets the handler function to be called when the WebSocket session is closed.
     *
     * This function allows to set a custom handler function to be called when the WebSocket session is closed.
     *
     * @param handler The handler function to be called when the WebSocket session is closed.
     */
    ws_client_handler &on_close(std::function<void()> &&handler) noexcept
    {
      on_close_handler = std::move(handler);
      return *this;
    }

    /**
     * @brief Sets the error handler for the WebSocket session.
     *
     * This function allows to set a custom error handler for the WebSocket session.
     * The error handler will be called when an error occurs during the WebSocket session.
     *
     * @param handler The error handler function to be called when an error occurs.
     * @return A reference to the `ws_client_handler` object.
     */
    ws_client_handler &on_error(std::function<void(const std::error_code &)> &&handler) noexcept
    {
      on_error_handler = std::move(handler);
      return *this;
    }

  private:
    std::function<void()> on_open_handler;                         // handler for the open event
    std::function<void(std::string_view)> on_message_handler;      // handler for the message event
    std::function<void()> on_close_handler;                        // handler for the close event
    std::function<void(const std::error_code &)> on_error_handler; // handler for the error event
  };

  class ws_client
  {
  public:
    ws_client(ws_client_handler handler, const std::string &host = SERVER_HOST, unsigned short port = SERVER_PORT);
    ~ws_client();

    /**
     * @brief Enqueues a message to be sent by the WebSocket session.
     *
     * This function adds a message to the session's outgoing message queue.
     * The message will be sent to the client when the session's write operation is ready.
     *
     * @param msg The message to enqueue.
     */
    void enqueue(utils::u_ptr<message> msg);

    /**
     * Sends a payload over the WebSocket session.
     *
     * @param payload The payload to be sent.
     */
    void send(utils::s_ptr<std::string> payload) { enqueue(utils::make_u_ptr<message>(payload)); }

    /**
     * Sends a message over the WebSocket session.
     *
     * @param payload The payload to be sent.
     */
    void send(std::string_view payload) { send(utils::make_s_ptr<std::string>(payload)); }

    /**
     * Sends a ping message to the WebSocket server.
     * This function enqueues a ping message with opcode 0x89 to the WebSocket session.
     */
    void ping() { enqueue(utils::make_u_ptr<message>(0x89)); }
    /**
     * Sends a pong message to the WebSocket client.
     * This function enqueues a pong message with opcode 0x8A to be sent to the WebSocket client.
     */
    void pong() { enqueue(utils::make_u_ptr<message>(0x8A)); }
    /**
     * @brief Closes the WebSocket session.
     *
     * This function enqueues a WebSocket close message with the opcode 0x88 to close the session.
     * The close message will be sent to the remote endpoint.
     */
    void close() { enqueue(utils::make_u_ptr<message>(0x88)); }

  private:
    void connect();

    void read();
    void write();

    void on_resolve(const std::error_code &ec, asio::ip::tcp::resolver::results_type results);
    void on_connect(const std::error_code &ec);

    void on_write(const std::error_code &ec, std::size_t bytes_transferred);

    void on_read(const std::error_code &ec, std::size_t bytes_transferred);
    void on_message(const std::error_code &ec, std::size_t bytes_transferred);

  private:
    ws_client_handler handler;        // The handler for the WebSocket client.
    const std::string host;           // The host name of the server.
    const unsigned short port;        // The port number of the server.
    asio::io_context io_ctx;          // The I/O context used for asynchronous operations.
    asio::ip::tcp::resolver resolver; // The resolver used to resolve host names.
#ifdef ENABLE_SSL
    asio::ssl::context ctx{asio::ssl::context::TLS_VERSION}; // The SSL context is required, and holds certificates
    asio::ssl::stream<asio::ip::tcp::socket> socket;         // The SSL socket used to communicate with the client.
#else
    asio::ip::tcp::socket socket; // The socket used to communicate with the client.
#endif
    asio::strand<asio::io_context::executor_type> strand; // The strand used to synchronize access to the queue of requests.
    std::queue<utils::u_ptr<message>> res_queue;          // The queue of responses to send to the server.
    utils::u_ptr<message> msg;                            // The current message being processed.
  };
} // namespace network
