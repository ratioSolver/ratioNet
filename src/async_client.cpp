#include "async_client.hpp"
#include "logging.hpp"

namespace network
{
#ifdef ENABLE_SSL
    async_client::async_client(std::string_view host, unsigned short port) : host(host), port(port), resolver(io_ctx), socket(io_ctx, ssl_ctx)
    {
        ssl_ctx.set_default_verify_paths();
        if (!SSL_set_tlsext_host_name(socket.native_handle(), host.data()))
        {
            LOG_ERR("SSL_set_tlsext_host_name failed");
            throw std::runtime_error("SSL_set_tlsext_host_name failed");
        }
        connect();
    }
#else
    async_client::async_client(std::string_view host, unsigned short port) : host(host), port(port), resolver(io_ctx), socket(io_ctx) { connect(); }
#endif

    async_client::~async_client() { disconnect(); }

    void async_client::connect()
    {
        asio::ip::tcp::resolver::query query(host, std::to_string(port));
        resolver.async_resolve(query, [this](const asio::error_code &ec, asio::ip::tcp::resolver::results_type results)
                               {
            if (!ec)
            {
                asio::async_connect(socket, results, [this](const asio::error_code &ec, const asio::ip::tcp::endpoint &) {
                    if (!ec)
                    {
#ifdef ENABLE_SSL
                        socket.async_handshake(asio::ssl::stream_base::client, [this](const asio::error_code &ec) {
                            if (!ec)
                            {
                                LOG_INFO("Connected to " << host << ":" << port);
                            }
                            else
                            {
                                LOG_ERR("SSL handshake failed: " << ec.message());
                                disconnect();
                            }
                        });
#else
                        LOG_INFO("Connected to " << host << ":" << port);
#endif
                    }
                    else
                    {
                        LOG_ERR("Failed to connect: " << ec.message());
                        disconnect();
                    }
                });
            }
            else
            {
                LOG_ERR("Failed to resolve host: " << ec.message());
                disconnect();
            } });
    }

    void async_client::disconnect()
    {
        if (socket.is_open())
        {
            socket.close();
            LOG_INFO("Disconnected from " << host << ":" << port);
        }
    }
} // namespace network
