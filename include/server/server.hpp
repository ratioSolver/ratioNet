#pragma once

#include <asio.hpp>
#ifdef ENABLE_SSL
#include <asio/ssl.hpp>
#endif

namespace network
{
  class server_session_base;

  class server_base
  {
    friend class server_session_base;

  public:
    /**
     * @brief Constructs a server_base instance with the specified host, port, and concurrency hint.
     *
     * @param host The hostname or IP address to bind the server to. Defaults to SERVER_HOST.
     * @param port The port number to listen on. Defaults to SERVER_PORT.
     * @param concurrency_hint The suggested number of threads for handling server operations.
     *        Defaults to the number of hardware threads available.
     */
    server_base(std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT, std::size_t concurrency_hint = std::thread::hardware_concurrency());
    /**
     * @brief Destroys the server_base instance.
     *
     * This destructor stops the server and cleans up resources.
     */
    virtual ~server_base();

    /**
     * @brief Starts the server.
     *
     * This function initializes the server, binds it to the specified host and port,
     * and begins listening for incoming connections. It also starts the thread pool
     * to handle incoming requests.
     */
    void start();

    /**
     * @brief Stops the server.
     *
     * This function stops the server, closes all connections, and joins all threads
     * in the thread pool. It should be called to gracefully shut down the server.
     */
    void stop();

  protected:
    void do_accept();

  private:
    virtual void on_accept(const std::error_code &ec, asio::ip::tcp::socket socket) = 0;

  private:
    asio::io_context io_ctx;                // The io_context is required for all I/O
    asio::signal_set signals;               // The signal_set is used to handle signals
    std::vector<std::thread> threads;       // The thread pool
    const asio::ip::tcp::endpoint endpoint; // The endpoint for the server
    asio::ip::tcp::acceptor acceptor;       // The acceptor for the server
  };

  class server : public server_base
  {
  public:
    /**
     * @brief Constructs a server instance with the specified host, port, and concurrency hint.
     *
     * @param host The hostname or IP address to bind the server to. Defaults to SERVER_HOST.
     * @param port The port number to listen on. Defaults to SERVER_PORT.
     * @param concurrency_hint The suggested number of threads for handling server operations.
     *        Defaults to the number of hardware threads available.
     */
    server(std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT, std::size_t concurrency_hint = std::thread::hardware_concurrency());

  private:
    /**
     * @brief Handles the accept operation for incoming connections.
     *
     * This function is called when a new connection is accepted.
     *
     * @param ec The error code indicating the result of the accept operation.
     * @param socket The accepted socket.
     */
    void on_accept(const std::error_code &ec, asio::ip::tcp::socket socket) override;
  };

#ifdef ENABLE_SSL
  class ssl_server : public server_base
  {
  public:
    /**
     * @brief Constructs an SSL server instance with the specified host, port, and concurrency hint.
     *
     * @param host The hostname or IP address to bind the server to. Defaults to SERVER_HOST.
     * @param port The port number to listen on. Defaults to SERVER_PORT.
     * @param concurrency_hint The suggested number of threads for handling server operations.
     *        Defaults to the number of hardware threads available.
     */
    ssl_server(std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT, std::size_t concurrency_hint = std::thread::hardware_concurrency());

  private:
    /**
     * @brief Handles the accept operation for incoming SSL connections.
     *
     * This function is called when a new SSL connection is accepted.
     *
     * @param ec The error code indicating the result of the accept operation.
     * @param socket The accepted SSL socket.
     */
    void on_accept(const std::error_code &ec, asio::ip::tcp::socket socket) override;

  private:
    asio::ssl::context ssl_ctx; // The SSL context used for secure connections
  };
#endif
} // namespace network
