#pragma once

#include "request.hpp"
#include "response.hpp"
#include <asio.hpp>
#include <queue>

namespace network
{
  class async_client_base;

  class client_session_base : public std::enable_shared_from_this<client_session_base>
  {
  public:
    /**
     * @brief Constructs a client_session instance.
     *
     * This constructor initializes the session with the provided client base.
     *
     * @param client The client base associated with this session.
     */
    explicit client_session_base(async_client_base &client);

    /**
     * @brief Destroys the client_session instance.
     */
    virtual ~client_session_base();

  private:
    async_client_base &client;                            // Reference to the client base associated with this session
    asio::strand<asio::io_context::executor_type> strand; // Strand to ensure thread-safe operations within the session
    std::queue<std::unique_ptr<request>> request_queue;   // Queue to hold outgoing requests
    std::queue<std::unique_ptr<response>> response_queue; // Queue to hold incoming responses
  };

  /**
   * @brief Represents a session in the client context.
   *
   * This class is used to manage the state and operations of a session within the client.
   * It inherits from client_session_base to provide common functionality for client sessions.
   */
  class client_session : public client_session_base
  {
  public:
    /**
     * @brief Constructs a client_session instance.
     *
     * This constructor initializes the session with the provided client base and socket.
     *
     * @param client The client base associated with this session.
     * @param socket The socket used to communicate with the server.
     */
    client_session(async_client_base &client, asio::ip::tcp::socket &&socket);

  private:
    asio::ip::tcp::socket socket; // The socket used to communicate with the server.
  };
} // namespace network
