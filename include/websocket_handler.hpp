#pragma once

#include "websocket_session.hpp"

namespace network
{
  class websocket_handler
  {
    friend class websocket_session;

  public:
    /**
     * @brief Called when a new client connects.
     *
     * @param session The session of the client.
     */
    websocket_handler &on_open(std::function<void(websocket_session &)> handler)
    {
      on_open_handler = handler;
      return *this;
    }

    /**
     * @brief Called when a client sends a message.
     *
     * @param session The session of the client.
     * @param msg The message sent by the client.
     */
    websocket_handler &on_message(std::function<void(websocket_session &, const std::string &)> handler)
    {
      on_message_handler = handler;
      return *this;
    }

    /**
     * @brief Called when a client disconnects.
     *
     * @param session The session of the client.
     * @param cr The reason for closing the connection.
     */
    websocket_handler &on_close(std::function<void(websocket_session &, const boost::beast::websocket::close_reason &)> handler)
    {
      on_close_handler = handler;
      return *this;
    }

    /**
     * @brief Called when an error occurs.
     *
     * @param session The session of the client.
     * @param ec The error code.
     */
    websocket_handler &on_error(std::function<void(websocket_session &, boost::beast::error_code const &)> handler)
    {
      on_error_handler = handler;
      return *this;
    }

  private:
    std::function<void(websocket_session &)> on_open_handler = [](websocket_session &) {};
    std::function<void(websocket_session &, const std::string &)> on_message_handler = [](websocket_session &, const std::string &) {};
    std::function<void(websocket_session &, const boost::beast::websocket::close_reason &)> on_close_handler = [](websocket_session &, const boost::beast::websocket::close_reason &) {};
    std::function<void(websocket_session &, boost::beast::error_code const &)> on_error_handler = [](websocket_session &, boost::beast::error_code const &) {};
  };
} // namespace network
