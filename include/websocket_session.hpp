#pragma once

#include <string>
#include <memory>
#include <boost/beast/websocket.hpp>

namespace network
{
  class server;
  class websocket_handler;

  class websocket_session
  {
  public:
    websocket_session(server &srv, websocket_handler &handler) : srv(srv), handler(handler) {}
    virtual ~websocket_session() = default;

    /**
     * @brief Send a message to the client.
     *
     * @param msg The message to send.
     */
    virtual void send(const std::shared_ptr<const std::string> &msg) = 0;
    /**
     * @brief Send a message to the client.
     *
     * @param message The message to send.
     */
    virtual void send(std::string &&message) { send(std::make_shared<std::string>(message)); }
    /**
     * @brief Close the connection to the client.
     *
     * @param cr The reason for closing the connection.
     */
    virtual void close(boost::beast::websocket::close_reason const &cr = boost::beast::websocket::close_code::normal) = 0;

  protected:
    server &srv;
    websocket_handler &handler;
  };
} // namespace network
