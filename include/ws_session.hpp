#pragma once

#include "message.hpp"
#ifdef ENABLE_SSL
#include <asio/ssl.hpp>
#endif
#include <queue>

namespace network
{
  class server;
  class session;

  /**
   * @brief Represents a WebSocket handler.
   *
   * The `ws_handler` class is responsible for handling WebSocket events such as open, message, close, and error.
   * Users can register callback functions for each event using the `on_open`, `on_message`, `on_close`, and `on_error` member functions.
   */
  class ws_handler
  {
    friend class server;

  public:
    ws_handler() = default;

    /**
     * @brief Registers a handler function to be called when the WebSocket session is opened.
     *
     * This function allows to set a custom handler function to be called when the WebSocket session is opened.
     * The handler function should take a reference to the `ws_session` object as its parameter.
     *
     * @param handler The handler function to be called when the WebSocket session is opened.
     *                The function takes a reference to the `ws_session` object as its parameter.
     */
    ws_handler &on_open(std::function<void(ws_session &)> &&handler) noexcept
    {
      on_open_handler = std::move(handler);
      return *this;
    }

    /**
     * @brief Registers a handler function to be called when a message is received.
     *
     * This function allows to set a custom handler function to be called when a message is received by the WebSocket session.
     * The handler function should take a reference to the `ws_session` object and a constant reference to the received message as its parameters.
     *
     * @param handler The handler function to be called. It takes a reference to the `ws_session` object and a constant reference to the received message.
     */
    ws_handler &on_message(std::function<void(ws_session &, std::string_view)> &&handler) noexcept
    {
      on_message_handler = std::move(handler);
      return *this;
    }

    /**
     * @brief Sets the handler function to be called when the WebSocket session is closed.
     *
     * This function allows to set a custom handler function to be called when the WebSocket session is closed.
     * The handler function should take a reference to the `ws_session` object as its parameter.
     *
     * @param handler The handler function to be called when the WebSocket session is closed.
     *                The function should take a reference to the `ws_session` object as its parameter.
     */
    ws_handler &on_close(std::function<void(ws_session &)> &&handler) noexcept
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
     *                The function should take a reference to the `ws_session` object as its parameter.
     * @return A reference to the `ws_handler` object.
     */
    ws_handler &on_error(std::function<void(ws_session &, const std::error_code &)> &&handler) noexcept
    {
      on_error_handler = std::move(handler);
      return *this;
    }

  private:
    std::function<void(ws_session &)> on_open_handler;                           // handler for the open event
    std::function<void(ws_session &, std::string_view)> on_message_handler;      // handler for the message event
    std::function<void(ws_session &)> on_close_handler;                          // handler for the close event
    std::function<void(ws_session &, const std::error_code &)> on_error_handler; // handler for the error event
  };

  /**
   * @class ws_session
   * @brief Represents a WebSocket session.
   *
   * The `ws_session` class is responsible for managing a WebSocket session between a client and a server.
   * It handles reading and writing messages, as well as managing the message queue for outgoing responses.
   *
   * This class is derived from `std::enable_shared_from_this` to allow shared ownership of the session object.
   *
   * @note This class is designed to be used in conjunction with the `server` and `session` classes.
   */
  class ws_session : public std::enable_shared_from_this<ws_session>
  {
    friend class server;
    friend class session;

  public:
#ifdef ENABLE_SSL
    /**
     * @brief Constructs a new WebSocket session object.
     *
     * This constructor is used to create a new WebSocket session object that will handle the communication
     * between the client and the server.
     *
     * @param srv The server that created the session.
     * @param path The path of the WebSocket session.
     * @param socket The SSL socket used to communicate with the client.
     */
    ws_session(server &srv, std::string_view path, asio::ssl::stream<asio::ip::tcp::socket> &&socket);
#else
    /**
     * @brief Constructs a new WebSocket session object.
     *
     * This constructor is used to create a new WebSocket session object that will handle the communication
     * between the client and the server.
     *
     * @param srv The server that created the session.
     * @param path The path of the WebSocket session.
     * @param socket The socket used to communicate with the client.
     */
    ws_session(server &srv, std::string_view path, asio::ip::tcp::socket &&socket);
#endif
    ~ws_session();

    /**
     * @brief Starts the session.
     *
     * This function starts the session and performs any necessary initialization.
     * It should be called before any other operations are performed on the session.
     */
    void start();

    /**
     * @brief Enqueues a response message to be sent by the WebSocket session.
     *
     * This function adds a response message to the session's outgoing message queue.
     * The message will be sent to the client when the session's write operation is ready.
     *
     * @param res The response message to enqueue.
     */
    void enqueue(utils::u_ptr<message> res);

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

    /**
     * @brief Get the remote endpoint of the WebSocket session.
     *
     * @return The remote endpoint of the WebSocket session.
     */
    asio::ip::tcp::endpoint remote_endpoint() const { return endpoint; }

  private:
    void read();
    void write();

    void on_read(const std::error_code &ec, std::size_t bytes_transferred);
    void on_message(const std::error_code &ec, std::size_t bytes_transferred);

    void on_write(const std::error_code &ec, std::size_t bytes_transferred);

  private:
    server &srv;                            // The server that created the session.
    std::string path;                       // The path of the WebSocket session.
    const asio::ip::tcp::endpoint endpoint; // The remote endpoint of the WebSocket session.
#ifdef ENABLE_SSL
    asio::ssl::stream<asio::ip::tcp::socket> socket; // The SSL socket used to communicate with the client.
#else
    asio::ip::tcp::socket socket; // The socket used to communicate with the client.
#endif
    utils::u_ptr<message> msg;                   // The message being read.
    std::queue<utils::u_ptr<message>> res_queue; // The queue of outgoing messages.
  };
} // namespace network
