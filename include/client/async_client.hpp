#pragma once

#include <asio.hpp>

namespace network
{
  class client_session_base;

  class async_client_base
  {
    friend class client_session_base;

  public:
    async_client_base(std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT);
    virtual ~async_client_base();

  protected:
    const std::string host;    // The host name of the server.
    const unsigned short port; // The port number of the server.
    asio::io_context io_ctx;   // The I/O context used for asynchronous operations.
  private:
    asio::ip::tcp::resolver resolver;                          // The resolver used to resolve host names.
    asio::ip::basic_resolver_results<asio::ip::tcp> endpoints; // The resolved endpoints for the server.
  };
} // namespace network
