#pragma once

#include "request.hpp"
#include "response.hpp"
#include <asio.hpp>
#ifdef ENABLE_SSL
#include <asio/ssl.hpp>
#endif
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
     * @brief Enqueues a request for processing.
     *
     * This method adds a request to the session's request queue for later processing.
     *
     * @param req The request to enqueue.
     */
    void enqueue(std::unique_ptr<request> req);
    /**
     * @brief Enqueues a response for sending.
     *
     * This method adds a response to the session's response queue for later sending.
     *
     * @param res The response to enqueue.
     */
    void enqueue(std::unique_ptr<response> res);

    /**
     * @brief Runs the session to process requests and responses.
     *
     * This method is responsible for reading requests, processing them, and sending responses.
     */
    void run();

  private:
    virtual void read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) = 0;
    virtual void read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) = 0;
    virtual void write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) = 0;

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

    void read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) override;
    void read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) override;
    void write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) override;

  private:
    asio::ip::tcp::socket socket; // The socket used to communicate with the client.
  };

#ifdef ENABLE_SSL
  /**
   * @brief Represents a secure session in the server context.
   *
   * This class is used to manage secure sessions within the server, inheriting from server_session_base.
   */
  class ssl_server_session : public server_session_base
  {
  public:
    /**
     * @brief Constructs a secure_server_session instance.
     *
     * @param srv The server base associated with this session.
     * @param socket The SSL socket used to communicate with the client.
     */
    ssl_server_session(server_base &srv, asio::ssl::stream<asio::ip::tcp::socket> &&socket);

    /**
     * @brief Initiates the SSL handshake.
     *
     * This method is called to perform the SSL handshake with the client.
     */
    void handshake(std::function<void(const std::error_code &)> callback);

    void read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) override;
    void read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) override;
    void write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) override;

  private:
    asio::ssl::stream<asio::ip::tcp::socket> socket; // The SSL socket used for secure communication.
  };
#endif
} // namespace network
