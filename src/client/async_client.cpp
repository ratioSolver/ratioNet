#include "async_client.hpp"
#include "client_session.hpp"
#include "logging.hpp"

namespace network
{
    async_client_base::async_client_base() : io_ctx(), work_guard(asio::make_work_guard(io_ctx))
    {
        io_thrd = std::thread([this]
                              { io_ctx.run(); });
    }
    async_client_base::~async_client_base()
    {
        io_ctx.stop(); // Stop the IO context to allow the thread to finish.
        if (io_thrd.joinable())
            io_thrd.join(); // Wait for the IO thread to finish.
    }

    std::shared_ptr<client_session_base> async_client_base::get_session(std::string_view host, unsigned short port)
    {
        std::string key = std::string(host) + ":" + std::to_string(port);
        if (auto it = sessions.find(key); it != sessions.end())
            return it->second; // Return existing session if found..

        // Create a new session if not found.
        auto session = create_session(host, port);
        session->connect(); // Initiate connection.
        sessions[key] = session;
        return session;
    }

    std::shared_ptr<ws_client_session_base> async_client_base::get_ws_session(std::string_view host, unsigned short port, std::string_view target)
    {
        std::string key = std::string(host) + ":" + std::to_string(port) + target.data();
        if (auto it = ws_sessions.find(key); it != ws_sessions.end())
            return it->second; // Return existing WebSocket session if found.

        // Create a new WebSocket session if not found.
        auto session = create_ws_session(host, port, target);
        session->connect(); // Initiate connection.
        ws_sessions[key] = session;
        return session;
    }

    async_client::async_client() : async_client_base() {}

    std::shared_ptr<client_session_base> async_client::create_session(std::string_view host, unsigned short port) { return std::make_shared<client_session>(*this, host, port, asio::ip::tcp::socket(io_ctx)); }

    std::shared_ptr<ws_client_session_base> async_client::create_ws_session(std::string_view host, unsigned short port, std::string_view target) { return std::make_shared<ws_client_session>(*this, host, port, target, asio::ip::tcp::socket(io_ctx)); }

#ifdef RATIONET_SSL
    ssl_async_client::ssl_async_client() : async_client_base(), ssl_ctx(asio::ssl::context::TLS_VERSION) { ssl_ctx.set_default_verify_paths(); }

    std::shared_ptr<client_session_base> ssl_async_client::create_session(std::string_view host, unsigned short port) { return std::make_shared<ssl_client_session>(*this, host, port, asio::ssl::stream<asio::ip::tcp::socket>(asio::ip::tcp::socket(io_ctx), ssl_ctx)); }

    std::shared_ptr<ws_client_session_base> ssl_async_client::create_ws_session(std::string_view host, unsigned short port, std::string_view target) { return std::make_shared<wss_client_session>(*this, host, port, target, asio::ssl::stream<asio::ip::tcp::socket>(asio::ip::tcp::socket(io_ctx), ssl_ctx)); }
#endif
} // namespace network