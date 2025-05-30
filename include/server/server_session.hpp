#pragma once

#include <memory>
#include <asio.hpp>

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

  private:
    server_base &server; // Reference to the server base associated with this session
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
    server_session(server_base &srv, asio::ip::tcp::socket &&socket);

  private:
    asio::ip::tcp::socket socket; // The socket used to communicate with the client.
  };
} // namespace network
