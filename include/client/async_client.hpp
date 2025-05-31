#pragma once

#include "request.hpp"
#include "response.hpp"
#include <asio.hpp>
#ifdef ENABLE_SSL
#include <asio/ssl.hpp>
#endif

namespace network
{
  class client_session_base;

  class async_client_base
  {
    friend class client_session_base;

  public:
    async_client_base(std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT);
    virtual ~async_client_base();

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
      send(std::make_unique<request>(verb::Get, std::move(target), "HTTP/1.1", std::move(hdrs)), std::move(cb));
    }

    /**
     * @brief Sends a request asynchronously and invokes a callback upon receiving the response.
     *
     * @param req A unique pointer to the request object to be sent.
     * @param cb A callback function to be called with the response once it is received.
     */
    void send(std::unique_ptr<request> req, std::function<void(const response &)> &&cb);

  protected:
    const std::string host;    // The host name of the server.
    const unsigned short port; // The port number of the server.
    asio::io_context io_ctx;   // The I/O context used for asynchronous operations.
  private:
    asio::ip::tcp::resolver resolver;                          // The resolver used to resolve host names.
    asio::ip::basic_resolver_results<asio::ip::tcp> endpoints; // The resolved endpoints for the server.
  };

  class async_client : public async_client_base
  {
  public:
    async_client(std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT);
  };

#ifdef ENABLE_SSL
  class ssl_async_client : public async_client_base
  {
  public:
    ssl_async_client(std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT);

  private:
    asio::ssl::context ssl_ctx; // The SSL context used for secure connections.
  };
#endif
} // namespace network
