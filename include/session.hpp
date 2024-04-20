#pragma once

#include <queue>
#include "request.hpp"
#include "response.hpp"

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
    session(server &srv, boost::asio::ip::tcp::socket &&socket);
    ~session();

  private:
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

    void on_read(const boost::system::error_code &ec, std::size_t bytes_transferred);
    void on_body(const boost::system::error_code &ec, std::size_t bytes_transferred);

    void on_write(const boost::system::error_code &ec, std::size_t bytes_transferred);

  private:
    server &srv;                                     // The server that created the session.
    boost::asio::ip::tcp::socket socket;             // The socket used to communicate with the client.
    std::unique_ptr<request> req;                    // The current request being processed.
    std::queue<std::unique_ptr<response>> res_queue; // The queue of responses to send to the client.
  };
} // namespace network
