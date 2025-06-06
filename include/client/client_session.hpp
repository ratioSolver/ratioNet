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
  class async_client_base;

  class client_session_base : public std::enable_shared_from_this<client_session_base>
  {
  public:
    /**
     * @brief Constructs a client_session_base instance.
     *
     * This constructor initializes the session with the provided client base and host/port.
     *
     * @param client The client base associated with this session.
     * @param host The host name of the server (default is SERVER_HOST).
     * @param port The port number of the server (default is SERVER_PORT).
     */
    explicit client_session_base(async_client_base &client, std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT);

    /**
     * @brief Destroys the client_session instance.
     */
    virtual ~client_session_base();

    void run();

  private:
    virtual void connect(asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, std::function<void(const asio::error_code &, const asio::ip::tcp::endpoint &)> callback) = 0;

    virtual void read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) = 0;
    virtual void read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) = 0;
    virtual void write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) = 0;

  protected:
    void enqueue(std::unique_ptr<request> req, std::function<void(const response &)> &&cb);
    void enqueue(std::unique_ptr<response> res, std::function<void(const response &)> &&cb);

  protected:
    async_client_base &client; // Reference to the client base associated with this session
    const std::string host;    // The host name of the server
    const unsigned short port; // The port number of the server
  private:
    asio::strand<asio::io_context::executor_type> strand;                                                   // Strand to ensure thread-safe operations within the session
    std::queue<std::pair<std::unique_ptr<request>, std::function<void(const response &)>>> request_queue;   // Queue to hold outgoing requests
    std::queue<std::pair<std::unique_ptr<response>, std::function<void(const response &)>>> response_queue; // Queue to hold incoming responses
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
    client_session(async_client_base &client, std::string_view host, unsigned short port, asio::ip::tcp::socket &&socket);

  private:
    void connect(asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, std::function<void(const asio::error_code &, const asio::ip::tcp::endpoint &)> callback) override;

    void read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) override;
    void read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) override;
    void write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) override;

  private:
    asio::ip::tcp::socket socket; // The socket used to communicate with the server.
  };

#ifdef ENABLE_SSL
  /**
   * @brief Represents a secure session in the client context.
   *
   * This class is used to manage the state and operations of a secure session within the client.
   * It inherits from client_session_base to provide common functionality for secure client sessions.
   */
  class ssl_client_session : public client_session_base
  {
  public:
    /**
     * @brief Constructs an ssl_client_session instance.
     *
     * This constructor initializes the session with the provided client base and SSL socket.
     *
     * @param client The client base associated with this session.
     * @param socket The SSL socket used to communicate with the server.
     */
    ssl_client_session(async_client_base &client, std::string_view host, unsigned short port, asio::ssl::stream<asio::ip::tcp::socket> &&socket);

  private:
    void connect(asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, std::function<void(const asio::error_code &, const asio::ip::tcp::endpoint &)> callback) override;

    void read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) override;
    void read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) override;
    void write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) override;

  private:
    asio::ssl::stream<asio::ip::tcp::socket> socket; // The SSL socket used to communicate with the server.
  };
#endif
} // namespace network
