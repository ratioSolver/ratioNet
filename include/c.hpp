#pragma once

#include "memory.hpp"
#include "request.hpp"
#include "response.hpp"
#include <queue>
#ifdef ENABLE_SSL
#include <asio/ssl.hpp>
#endif

namespace network
{
  class sync_client
  {
  public:
    sync_client(std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT);
    virtual ~sync_client();

    /**
     * Sends a request and returns the response.
     *
     * @param req The request to be sent.
     * @return The response received.
     */
    utils::u_ptr<response> send(utils::u_ptr<request> req);

  private:
    virtual bool is_connected() const = 0; // Check if the client is connected to the server.

    virtual asio::ip::tcp::endpoint connect(const asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, asio::error_code &ec) = 0;
    virtual std::size_t read(asio::streambuf &buffer, std::size_t size, asio::error_code &ec) = 0;
    virtual std::size_t read_until(asio::streambuf &buffer, std::string_view delimiter, asio::error_code &ec) = 0;
    virtual std::size_t write(asio::streambuf &buffer, asio::error_code &ec) = 0;
    virtual void disconnect(asio::error_code &ec);

  protected:
    asio::io_context io_ctx; // The I/O context used for asynchronous operations.
  private:
    asio::ip::tcp::resolver resolver;                          // The resolver used to resolve host names.
    asio::ip::basic_resolver_results<asio::ip::tcp> endpoints; // The resolved endpoints for the server.
  };

  class client : public sync_client
  {
  public:
    /**
     * @brief Constructs an http_client object with the specified host and port.
     *
     * @param host The host name of the server.
     * @param port The port number of the server.
     */
    client(std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT);

  private:
    bool is_connected() const override;

    asio::ip::tcp::endpoint connect(const asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, asio::error_code &ec) override;
    std::size_t read(asio::streambuf &buffer, std::size_t size, asio::error_code &ec) override;
    std::size_t read_until(asio::streambuf &buffer, std::string_view delimiter, asio::error_code &ec) override;
    std::size_t write(asio::streambuf &buffer, asio::error_code &ec);
    void disconnect(asio::error_code &ec) override;

  private:
    asio::ip::tcp::socket socket; // The TCP socket used to communicate with the server.
  };

#ifdef ENABLE_SSL
  class ssl_client : public sync_client
  {
  public:
    /**
     * @brief Constructs an ssl_client object with the specified host and port.
     *
     * @param host The host name of the server.
     * @param port The port number of the server.
     */
    ssl_client(std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT);

  private:
    bool is_connected() const override;

    asio::ip::tcp::endpoint connect(const asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, asio::error_code &ec) override;
    std::size_t read(asio::streambuf &buffer, std::size_t size, asio::error_code &ec) override;
    std::size_t read_until(asio::streambuf &buffer, std::string_view delimiter, asio::error_code &ec) override;
    std::size_t write(asio::streambuf &buffer, asio::error_code &ec);
    void disconnect(asio::error_code &ec) override;

  private:
    const std::string host;                          // The host name of the server.
    asio::ssl::context ssl_ctx;                      // The SSL context used for secure communication.
    asio::ssl::stream<asio::ip::tcp::socket> socket; // The SSL socket used to communicate with the server.
  };
#endif
} // namespace network
