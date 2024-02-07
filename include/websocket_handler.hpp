#pragma once

#include "websocket_session.hpp"

namespace network
{
  class server_response
  {
  public:
    virtual ~server_response() = default;
  };

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
    websocket_handler &on_message(std::function<void(websocket_session &, std::shared_ptr<const std::string>)> handler)
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
    websocket_handler &on_close(std::function<void(websocket_session &, boost::beast::websocket::close_reason const &)> handler)
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
    std::function<void(websocket_session &, std::shared_ptr<const std::string>)> on_message_handler = [](websocket_session &, std::shared_ptr<const std::string>) {};
    std::function<void(websocket_session &, boost::beast::websocket::close_reason const &)> on_close_handler = [](websocket_session &, boost::beast::websocket::close_reason const &) {};
    std::function<void(websocket_session &, boost::beast::error_code const &)> on_error_handler = [](websocket_session &, boost::beast::error_code const &) {};
  };
} // namespace network
