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
  class async_client_base
  {
  public:
    /**
     * @brief Constructs an async_client object with the specified host and port.
     *
     * @param host The host name of the server.
     * @param port The port number of the server.
     */
    async_client_base(std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT);
    virtual ~async_client_base() = default;

    /**
     * @brief Sends a request asynchronously and invokes a callback upon receiving the response.
     *
     * @param req A unique pointer to the request object to be sent.
     * @param cb A callback function to be called with the response once it is received.
     */
    void send(utils::u_ptr<request> req, std::function<void(const response &)> &&cb);

    /**
     * @brief Sends a GET request asynchronously.
     *
     * @param target The target URL or path.
     * @param cb A callback function to be called with the response once it is received.
     * @param hdrs Optional headers to include in the request.
     */
    void get(std::string &&target, std::function<void(const response &)> &&cb, std::map<std::string, std::string> &&hdrs = {})
    {
      hdrs["Host"] = host + ":" + std::to_string(port);
      send(utils::make_u_ptr<request>(verb::Get, std::move(target), "HTTP/1.1", std::move(hdrs)), std::move(cb));
    }

  protected:
    void on_connect(const asio::error_code &ec, const asio::ip::tcp::endpoint &endpoint);
    void on_write(const asio::error_code &ec, std::size_t bytes_transferred);

  private:
    /**
     * @brief Checks if the client is currently connected.
     *
     * @return true if the client is connected; false otherwise.
     */
    virtual bool is_connected() const = 0;
    /**
     * @brief Connects to the server using the resolved endpoints.
     *
     * @param endpoints The resolved endpoints for the server.
     */
    virtual void connect(const asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints) = 0;
    /**
     * @brief Disconnects the client from the server.
     */
    virtual void disconnect() = 0;

    virtual void write(asio::streambuf &buffer) = 0;

  protected:
    const std::string host;                                                // The host name of the server.
    const unsigned short port;                                             // The port number of the server.
    asio::io_context io_ctx;                                               // The I/O context used for asynchronous operations.
    asio::executor_work_guard<asio::io_context::executor_type> work_guard; // Work guard to keep the io_context running.
    std::thread io_thrd;                                                   // Thread for processing asynchronous operations.
  private:
    asio::ip::tcp::resolver resolver;                                                                  // The resolver used to resolve host names.
    asio::ip::basic_resolver_results<asio::ip::tcp> endpoints;                                         // The resolved endpoints for the server.
    std::queue<std::pair<utils::u_ptr<request>, std::function<void(const response &)>>> request_queue; // Queue for pending requests.
  };

  class async_client : public async_client_base
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

  private:
    /**
     * @brief Checks if the client is currently connected.
     *
     * @return true if the client is connected; false otherwise.
     */
    bool is_connected() const override;
    /**
     * @brief Connects to the server using the resolved endpoints.
     *
     * @param endpoints The resolved endpoints for the server.
     */
    void connect(const asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints) override;
    /**
     * @brief Disconnects the client from the server.
     */
    void disconnect() override;

    void write(asio::streambuf &buffer) override;

  private:
    asio::ip::tcp::socket socket; // The TCP socket used to communicate with the server.
  };

#ifdef ENABLE_SSL
  class async_ssl_client : public async_client_base
  {
  public:
    /**
     * @brief Constructs an async_ssl_client object with the specified host and port.
     *
     * @param host The host name of the server.
     * @param port The port number of the server.
     */
    async_ssl_client(std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT);
    ~async_ssl_client();

  private:
    /**
     * @brief Checks if the client is currently connected.
     *
     * @return true if the client is connected; false otherwise.
     */
    bool is_connected() const override;
    /**
     * @brief Connects to the server using the resolved endpoints.
     *
     * @param endpoints The resolved endpoints for the server.
     */
    void connect(const asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints) override;
    /**
     * @brief Disconnects the client from the server.
     */
    void disconnect() override;

    void write(asio::streambuf &buffer) override;

  private:
    asio::ssl::context ssl_ctx;                      // SSL context for secure communication.
    asio::ssl::stream<asio::ip::tcp::socket> socket; // SSL stream for secure communication.
  };
#endif
} // namespace network
