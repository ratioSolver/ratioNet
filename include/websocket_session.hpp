#pragma once

#include <string>
#include <memory>
#include <boost/beast.hpp>
#ifdef USE_SSL
#include <boost/beast/ssl.hpp>
#endif
#include <boost/beast/websocket.hpp>

namespace network
{
  class base_server;
  class websocket_handler;

  class websocket_session
  {
  public:
    websocket_session(base_server &srv, websocket_handler &handler) : srv(srv), handler(handler) {}
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
    void send(std::string &&message) { send(std::make_shared<std::string>(message)); }
    /**
     * @brief Close the connection to the client.
     *
     * @param cr The reason for closing the connection.
     */
    virtual void close(boost::beast::websocket::close_reason const &cr = boost::beast::websocket::close_code::normal) = 0;

  protected:
    void fire_on_open();
    void fire_on_message(const std::string &msg);
    void fire_on_close(boost::beast::websocket::close_reason const &cr);
    void fire_on_error(boost::beast::error_code const &ec);

  protected:
    base_server &srv;
    websocket_handler &handler;
    boost::beast::flat_buffer buffer;
  };

  class plain_websocket_session : public websocket_session
  {
  public:
    plain_websocket_session(network::base_server &srv, boost::beast::tcp_stream &&str, websocket_handler &handler) : network::websocket_session(srv, handler), websocket(std::move(str)) {}

  protected:
    boost::beast::websocket::stream<boost::beast::tcp_stream> websocket;
  };

#ifdef USE_SSL
  class ssl_websocket_session : public websocket_session
  {
  public:
    ssl_websocket_session(network::base_server &srv, boost::beast::ssl_stream<boost::beast::tcp_stream> &&str, websocket_handler &handler) : network::websocket_session(srv, handler), websocket(std::move(str)) {}

  protected:
    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>> websocket;
  };
#endif
} // namespace network
