#pragma once

#include "memory.hpp"
#include "request.hpp"
#include "response.hpp"
#include <queue>
#ifdef ENABLE_SSL
#include <asio/ssl.hpp>
#endif

namespace network
{
  class async_client
  {
  public:
    /**
     * @brief Constructs an async_client object with the specified host and port.
     *
     * @param host The host name of the server.
     * @param port The port number of the server.
     */
    async_client(std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT);
    ~async_client();

    /**
     * @brief Sends a request asynchronously and invokes the provided callback upon receiving a response.
     *
     * This function takes ownership of the given request and sends it asynchronously.
     * Once a response is received, the specified callback function is called with the response as its argument.
     *
     * @param req A unique pointer to the request object to be sent.
     * @param callback A callable object (e.g., lambda or function) that will be invoked with the received response.
     */
    void send(utils::u_ptr<request> req, std::function<void(const response &)> &&callback);

  private:
    /**
     * @brief Connects the client to the server.
     *
     * This function establishes a connection to the server using the specified host and port.
     */
    void connect();

    /**
     * @brief Disconnects the client from the server.
     */
    void disconnect();

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
  };
} // namespace network
