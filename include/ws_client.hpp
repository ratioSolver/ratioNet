#pragma once

#include "memory.hpp"
#include "message.hpp"
#ifdef ENABLE_SSL
#include <asio/ssl.hpp>
#endif
#include <queue>

namespace network
{
  class ws_client
  {
  public:
    ws_client(const std::string &host = SERVER_HOST, unsigned short port = SERVER_PORT, std::function<void()> on_open_handler = []() {}, std::function<void(std::string_view)> on_message_handler = [](std::string_view) {}, std::function<void()> on_close_handler = []() {}, std::function<void(const std::error_code &)> on_error_handler = [](const std::error_code &) {});
    ~ws_client();

    /**
     * @brief Disconnects the client from the server.
     */
    void disconnect();

  private:
    void connect();

  private:
    const std::string host;    // The host name of the server.
    const unsigned short port; // The port number of the server.
    asio::io_context io_ctx;   // The I/O context used for asynchronous operations.
#ifdef ENABLE_SSL
    asio::ssl::context ssl_ctx{asio::ssl::context::TLS_VERSION}; // The SSL context used for secure communication.
#endif
    asio::ip::tcp::resolver resolver; // The resolver used to resolve host names.
#ifdef ENABLE_SSL
    asio::ssl::stream<asio::ip::tcp::socket> socket; // The SSL socket used to communicate with the server.
#else
    asio::ip::tcp::socket socket; // The socket used to communicate with the server.
#endif
    std::function<void()> on_open_handler;                         // The handler for the open event.
    std::function<void(std::string_view)> on_message_handler;      // The handler for the message event.
    std::function<void()> on_close_handler;                        // The handler for the close event.
    std::function<void(const std::error_code &)> on_error_handler; // The handler for the error event.
  };
} // namespace network
