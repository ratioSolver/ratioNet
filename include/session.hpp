#pragma once

#include "request.hpp"
#include "response.hpp"
#ifdef ENABLE_SSL
#include <asio/ssl.hpp>
#endif
#include <queue>

namespace network
{
  class server;

  /**
   * @class session
   * @brief Represents a session between a client and the server.
   *
   * The session class is responsible for handling the communication between a client and the server.
   * It manages reading requests from the client, writing responses back to the client, and maintaining
   * the state of the session.
   */
  class session : public std::enable_shared_from_this<session>
  {
    friend class server;

  public:
#ifdef ENABLE_SSL
    /**
     * @brief Constructs a new session object.
     *
     * This constructor is used to create a new session object that will handle the communication
     * between the client and the server.
     *
     * @param srv The server that created the session.
     * @param socket The SSL socket used to communicate with the client.
     */
    session(server &srv, asio::ssl::stream<asio::ip::tcp::socket> &&socket);
#else
    /**
     * @brief Constructs a new session object.
     *
     * This constructor is used to create a new session object that will handle the communication
     * between the client and the server.
     *
     * @param srv The server that created the session.
     * @param socket The socket used to communicate with the client.
     */
    session(server &srv, asio::ip::tcp::socket &&socket);
#endif
    ~session();

  private:
#ifdef ENABLE_SSL
    /**
     * @brief Performs the SSL handshake with the client.
     */
    void handshake();

    /**
     * @brief Handler for the SSL handshake.
     *
     * This function is called when the SSL handshake with the client is completed.
     *
     * @param ec The error code returned by the handshake operation.
     */
    void on_handshake(const std::error_code &ec);
#endif
    /**
     * @brief Reads a request from the client.
     */
    void read();
    /**
     * Enqueues a response to the responses queue.
     *
     * This function adds a response to the responses queue. The response will be
     * processed asynchronously by the session.
     *
     * @param res A unique pointer to the response object to be enqueued.
     */
    void enqueue(std::unique_ptr<response> res);
    /**
     * @brief Writes the first response, from the responses queue, to the client.
     */
    void write();

    /**
     * @brief Upgrades the session to a WebSocket connection.
     */
    void upgrade();

    void on_read(const std::error_code &ec, std::size_t bytes_transferred);
    void on_body(const std::error_code &ec, std::size_t bytes_transferred);

    void on_write(const std::error_code &ec, std::size_t bytes_transferred);

  private:
    server &srv;                            // The server that created the session.
    const asio::ip::tcp::endpoint endpoint; // The endpoint of the client.
#ifdef ENABLE_SSL
    asio::ssl::stream<asio::ip::tcp::socket> socket; // The SSL socket used to communicate with the client.
#else
    asio::ip::tcp::socket socket; // The socket used to communicate with the client.
#endif
    std::unique_ptr<request> req;                         // The current request being processed.
    asio::strand<asio::io_context::executor_type> strand; // The strand used to synchronize access to the queue of responses.
    std::queue<std::unique_ptr<response>> res_queue;      // The queue of responses to send to the client.
  };
} // namespace network
