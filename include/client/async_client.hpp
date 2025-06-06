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
    async_client_base();
    virtual ~async_client_base();

    std::shared_ptr<client_session_base> get_session(std::string_view host, unsigned short port);

  private:
    virtual std::shared_ptr<client_session_base> create_session(std::string_view host, unsigned short port) = 0;

  protected:
    asio::io_context io_ctx; // The I/O context used for asynchronous operations.
  private:
    std::unordered_map<std::string, std::shared_ptr<client_session_base>> sessions; // A map of active client sessions.
    asio::executor_work_guard<asio::io_context::executor_type> work_guard;          // Work guard to keep the io_context running.
    std::thread io_thrd;                                                            // Thread for processing asynchronous operations.
  };

  class async_client : public async_client_base
  {
  public:
    async_client();

    std::shared_ptr<client_session_base> create_session(std::string_view host, unsigned short port) override;
  };

#ifdef ENABLE_SSL
  class ssl_async_client : public async_client_base
  {
  public:
    ssl_async_client();

    std::shared_ptr<client_session_base> create_session(std::string_view host, unsigned short port) override;

  private:
    asio::ssl::context ssl_ctx; // The SSL context used for secure connections.
  };
#endif
} // namespace network
