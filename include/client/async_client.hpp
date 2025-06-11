#pragma once

#include "client_session.hpp"
#include "ws_client_session.hpp"

namespace network
{
  class async_client_base
  {
    friend class client_session_base;
    friend class ws_client_session_base;

  public:
    async_client_base();
    virtual ~async_client_base();

    std::shared_ptr<client_session_base> get_session(std::string_view host, unsigned short port);

    std::shared_ptr<ws_client_session_base> get_ws_session(std::string_view host, unsigned short port, std::string_view target);

  private:
    virtual std::shared_ptr<client_session_base> create_session(std::string_view host, unsigned short port) = 0;

    virtual std::shared_ptr<ws_client_session_base> create_ws_session(std::string_view host, unsigned short port, std::string_view target) = 0;

  protected:
    asio::io_context io_ctx; // The I/O context used for asynchronous operations.
  private:
    std::unordered_map<std::string, std::shared_ptr<client_session_base>> sessions; // A map of active client sessions.
    std::unordered_map<std::string, std::shared_ptr<ws_client_session_base>> ws_sessions; // A map of active WebSocket client sessions.
    asio::executor_work_guard<asio::io_context::executor_type> work_guard;          // Work guard to keep the io_context running.
    std::thread io_thrd;                                                            // Thread for processing asynchronous operations.
  };

  class async_client : public async_client_base
  {
  public:
    async_client();

    std::shared_ptr<client_session_base> create_session(std::string_view host, unsigned short port) override;

    std::shared_ptr<ws_client_session_base> create_ws_session(std::string_view host, unsigned short port, std::string_view target) override;
  };

#ifdef ENABLE_SSL
  class ssl_async_client : public async_client_base
  {
  public:
    ssl_async_client();

    std::shared_ptr<client_session_base> create_session(std::string_view host, unsigned short port) override;

    std::shared_ptr<ws_client_session_base> create_ws_session(std::string_view host, unsigned short port, std::string_view target) override;

  private:
    asio::ssl::context ssl_ctx; // The SSL context used for secure connections.
  };
#endif
} // namespace network
