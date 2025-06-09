#pragma once

#include <functional>
#include <string_view>
#include <system_error>

namespace network
{
  class server_base;
  class ws_server_session_base;

  /**
   * @brief Represents a WebSocket handler.
   *
   * The `ws_handler` class is responsible for handling WebSocket events such as open, message, close, and error.
   * Users can register callback functions for each event using the `on_open`, `on_message`, `on_close`, and `on_error` member functions.
   */
  class ws_handler
  {
    friend class server_base;

  public:
    ws_handler() = default;

    /**
     * @brief Registers a handler function to be called when the WebSocket session is opened.
     *
     * This function allows to set a custom handler function to be called when the WebSocket session is opened.
     * The handler function should take a reference to the `ws_server_session_base` object as its parameter.
     *
     * @param handler The handler function to be called when the WebSocket session is opened.
     *                The function takes a reference to the `ws_server_session_base` object as its parameter.
     */
    ws_handler &on_open(std::function<void(ws_server_session_base &)> &&handler) noexcept
    {
      on_open_handler = std::move(handler);
      return *this;
    }

    /**
     * @brief Registers a handler function to be called when a message is received.
     *
     * This function allows to set a custom handler function to be called when a message is received by the WebSocket session.
     * The handler function should take a reference to the `ws_server_session_base` object and a constant reference to the received message as its parameters.
     *
     * @param handler The handler function to be called. It takes a reference to the `ws_server_session_base` object and a constant reference to the received message.
     */
    ws_handler &on_message(std::function<void(ws_server_session_base &, std::string_view)> &&handler) noexcept
    {
      on_message_handler = std::move(handler);
      return *this;
    }

    /**
     * @brief Sets the handler function to be called when the WebSocket session is closed.
     *
     * This function allows to set a custom handler function to be called when the WebSocket session is closed.
     * The handler function should take a reference to the `ws_server_session_base` object as its parameter.
     *
     * @param handler The handler function to be called when the WebSocket session is closed.
     *                The function should take a reference to the `ws_server_session_base` object as its parameter.
     */
    ws_handler &on_close(std::function<void(ws_server_session_base &)> &&handler) noexcept
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
     *                The function should take a reference to the `ws_server_session_base` object as its parameter.
     * @return A reference to the `ws_handler` object.
     */
    ws_handler &on_error(std::function<void(ws_server_session_base &, const std::error_code &)> &&handler) noexcept
    {
      on_error_handler = std::move(handler);
      return *this;
    }

  private:
    std::function<void(ws_server_session_base &)> on_open_handler;                           // handler for the open event
    std::function<void(ws_server_session_base &, std::string_view)> on_message_handler;      // handler for the message event
    std::function<void(ws_server_session_base &)> on_close_handler;                          // handler for the close event
    std::function<void(ws_server_session_base &, const std::error_code &)> on_error_handler; // handler for the error event
  };
} // namespace network
