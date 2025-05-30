#pragma once

#include "request.hpp"
#include "response.hpp"
#include <asio.hpp>
#include <queue>

namespace network
{
  class server_base;

  class server_session_base : public std::enable_shared_from_this<server_session_base>
  {
  public:
    /**
     * @brief Constructs a server_session_base instance.
     *
     * This constructor initializes the session with the provided server base.
     *
     * @param server The server base associated with this session.
     */
    explicit server_session_base(server_base &server);

    /**
     * @brief Destroys the server_session_base instance.
     */
    virtual ~server_session_base();

    /**
     * @brief Starts the session by initiating the read operation.
     *
     * This function is called to start the session and begin reading requests.
     */
    virtual void read() = 0;

    /**
     * @brief Handles the read operation for incoming requests.
     *
     * @param req The request object to be filled with data.
     * @param ec The error code indicating the result of the read operation.
     * @param bytes_transferred The number of bytes transferred during the read operation.
     */
    void on_read(request &req, const std::error_code &ec, std::size_t bytes_transferred);

  protected:
    request &create_request();

  private:
    server_base &server;                                  // Reference to the server base associated with this session
    asio::strand<asio::io_context::executor_type> strand; // Strand to ensure thread-safe operations within the session
    std::queue<std::unique_ptr<request>> request_queue;   // Queue to hold incoming requests
    std::queue<std::unique_ptr<response>> response_queue; // Queue to hold outgoing responses
  };

  /**
   * @brief Represents a session in the server context.
   *
   * This class is used to manage the state and operations of a session within the server.
   * It inherits from server_session_base to provide common functionality for server sessions.
   */
  class server_session : public server_session_base
  {
  public:
    /**
     * @brief Constructs a server_session instance.
     *
     * This constructor initializes the session with the provided server base and socket.
     *
     * @param srv The server base associated with this session.
     * @param socket The socket used to communicate with the client.
     */
    server_session(server_base &srv, asio::ip::tcp::socket &&socket);

  private:
    /**
     * @brief Performs the read operation to receive requests from the client.
     */
    void read() override;

  private:
    asio::ip::tcp::socket socket; // The socket used to communicate with the client.
  };
} // namespace network
