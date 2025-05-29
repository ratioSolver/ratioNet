#include "async_client.hpp"
#include "logging.hpp"

namespace network
{
#ifdef ENABLE_SSL
    async_client::async_client(std::string_view host, unsigned short port) : host(host), port(port), work_guard(asio::make_work_guard(io_ctx)), resolver(io_ctx), endpoints(resolver.resolve(host, std::to_string(port))), socket(io_ctx, ssl_ctx)
    {
        ssl_ctx.set_default_verify_paths();
        if (!SSL_set_tlsext_host_name(socket.native_handle(), host.data()))
        {
            LOG_ERR("SSL_set_tlsext_host_name failed");
            throw std::runtime_error("SSL_set_tlsext_host_name failed");
        }
        connect();
        io_thrd = std::thread([this]
                              { io_ctx.run(); });
    }
#else
    async_client::async_client(std::string_view host, unsigned short port) : host(host), port(port), work_guard(asio::make_work_guard(io_ctx)), resolver(io_ctx), endpoints(resolver.resolve(host, std::to_string(port))), socket(io_ctx)
    {
        connect();
        io_thrd = std::thread([this]
                              { io_ctx.run(); });
    }
#endif

    async_client::~async_client()
    {
        disconnect();
        work_guard.reset();
        io_ctx.stop();
        if (io_thrd.joinable())
            io_thrd.join();
    }

    void async_client::send(utils::u_ptr<request> &&req, std::function<void(const response &)> &&cb)
    {
        asio::post(io_ctx, [this, req = std::move(req), cb = std::move(cb)]
                   { process_requests(); });
    }

    void async_client::connect()
    {
        asio::ip::tcp::resolver::query query(host, std::to_string(port));
        resolver.async_resolve(query, [this](const asio::error_code &ec, asio::ip::tcp::resolver::results_type results)
                               {
            if (!ec)
            {
#ifdef ENABLE_SSL
                asio::async_connect(socket.lowest_layer(), results, [this](const asio::error_code &ec, const asio::ip::tcp::endpoint &)
                {
                    if (!ec)
                    {
                        socket.set_verify_mode(asio::ssl::verify_peer);
                        socket.set_verify_callback(asio::ssl::host_name_verification(host));
                        socket.async_handshake(asio::ssl::stream_base::client, [this](const asio::error_code &ec)
                        {
                            if (ec)
                            {
                                LOG_ERR("SSL handshake failed: " << ec.message());
                                disconnect();
                            }
                            else
                            {
                                LOG_DEBUG("Connected to " << host << ":" << port);
                                // Start processing requests after successful connection..
                                process_requests();
                            }
                        });
                    }
                    else
                    {
                        LOG_ERR("Failed to connect: " << ec.message());
                        disconnect();
                    }
                });
#else
                asio::async_connect(socket, results, [this](const asio::error_code &ec, const asio::ip::tcp::endpoint &endpoint)
                {
                    if (!ec)
                    {
                        LOG_DEBUG("Connected to " << host << ":" << port);
                    }
                    else
                    {
                        LOG_ERR("Failed to connect: " << ec.message());
                        disconnect();
                    }
                });
#endif
            }
            else
            {
                LOG_ERR("Failed to resolve host: " << ec.message());
                disconnect();
            } });
    }

    void async_client::disconnect()
    {
#ifdef ENABLE_SSL
        if (socket.lowest_layer().is_open())
        {
            asio::error_code ec;
            socket.lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            socket.lowest_layer().close(ec);
            if (ec)
                LOG_ERR("Failed to close socket: " << ec.message());
        }
#else
        if (socket.is_open())
        {
            asio::error_code ec;
            socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            socket.close(ec);
            if (ec)
                LOG_ERR("Failed to close socket: " << ec.message());
        }
#endif
        LOG_DEBUG("Disconnected from " << host << ":" << port);
    }

    void async_client::process_requests()
    {
    }
} // namespace network
