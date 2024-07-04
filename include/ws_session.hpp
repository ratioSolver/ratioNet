#pragma once

#include <queue>
#include "message.hpp"

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
    ws_handler &on_message(std::function<void(ws_session &, const std::string &)> &&handler) noexcept
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
    ws_handler &on_error(std::function<void(ws_session &, const boost::system::error_code &)> &&handler) noexcept
    {
      on_error_handler = std::move(handler);
      return *this;
    }

  private:
    std::function<void(ws_session &)> on_open_handler;                                     // handler for the open event
    std::function<void(ws_session &, const std::string &)> on_message_handler;             // handler for the message event
    std::function<void(ws_session &)> on_close_handler;                                    // handler for the close event
    std::function<void(ws_session &, const boost::system::error_code &)> on_error_handler; // handler for the error event
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
    ws_session(server &srv, const std::string &path, boost::asio::ip::tcp::socket &&socket);
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
    void enqueue(std::unique_ptr<message> res);

    /**
     * Sends a payload over the WebSocket session.
     *
     * @param payload The payload to be sent.
     */
    void send(std::shared_ptr<std::string> payload) { enqueue(std::make_unique<message>(payload)); }

    /**
     * Sends a message over the WebSocket session.
     *
     * @param payload The payload to be sent.
     */
    void send(const std::string &payload) { send(std::make_shared<std::string>(payload)); }

    /**
     * Sends a ping message to the WebSocket server.
     * This function enqueues a ping message with opcode 0x89 to the WebSocket session.
     */
    void ping() { enqueue(std::make_unique<message>(0x89)); }
    /**
     * Sends a pong message to the WebSocket client.
     * This function enqueues a pong message with opcode 0x8A to be sent to the WebSocket client.
     */
    void pong() { enqueue(std::make_unique<message>(0x8A)); }
    /**
     * @brief Closes the WebSocket session.
     *
     * This function enqueues a WebSocket close message with the opcode 0x88 to close the session.
     * The close message will be sent to the remote endpoint.
     */
    void close() { enqueue(std::make_unique<message>(0x88)); }

    /**
     * @brief Get the remote endpoint of the WebSocket session.
     *
     * @return The remote endpoint of the WebSocket session.
     */
    boost::asio::ip::tcp::endpoint remote_endpoint() const { return socket.remote_endpoint(); }

  private:
    void read();
    void write();

    void on_read(const boost::system::error_code &ec, std::size_t bytes_transferred);
    void on_message(const boost::system::error_code &ec, std::size_t bytes_transferred);

    void on_write(const boost::system::error_code &ec, std::size_t bytes_transferred);

  private:
    server &srv;                                    // reference to the server
    std::string path;                               // path of the WebSocket session
    boost::asio::ip::tcp::socket socket;            // socket for the session
    std::unique_ptr<message> msg;                   // message being read
    std::queue<std::unique_ptr<message>> res_queue; // queue for the responses
  };
} // namespace network
