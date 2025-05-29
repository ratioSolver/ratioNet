#pragma once

#include "memory.hpp"
#include "request.hpp"
#include "response.hpp"
#include <queue>
#ifdef ENABLE_SSL
#include <asio/ssl.hpp>
#endif
#include <thread>

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
     * @brief Sends a request asynchronously and invokes a callback upon receiving the response.
     *
     * @param req A unique pointer to the request object to be sent.
     * @param cb A callback function to be called with the response once it is received.
     */
    void send(utils::u_ptr<request> &&req, std::function<void(const response &)> &&cb);

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

    /**
     * @brief Processes the requests in the queue.
     *
     * This function retrieves requests from the queue and sends them to the server.
     * It also handles the responses by invoking the corresponding callbacks.
     */
    void process_requests();

  private:
    const std::string host;                                                // The host name of the server.
    const unsigned short port;                                             // The port number of the server.
    asio::io_context io_ctx;                                               // The I/O context used for asynchronous operations.
    asio::executor_work_guard<asio::io_context::executor_type> work_guard; // Work guard to keep the io_context running.
#ifdef ENABLE_SSL
    asio::ssl::context ssl_ctx{asio::ssl::context::TLS_VERSION}; // The SSL context used for secure communication.
#endif
    asio::ip::tcp::resolver resolver;                          // The resolver used to resolve host names.
    asio::ip::basic_resolver_results<asio::ip::tcp> endpoints; // The resolved endpoints for the server.
#ifdef ENABLE_SSL
    asio::ssl::stream<asio::ip::tcp::socket> socket; // The SSL socket used to communicate with the server.
#else
    asio::ip::tcp::socket socket; // The socket used to communicate with the server.
#endif
    std::queue<std::pair<utils::u_ptr<request>, std::function<void(const response &)>>> requests; // Queue to store requests and their corresponding callbacks
    std::thread io_thrd;                                                                          // Thread for processing asynchronous operations
  };
} // namespace network
