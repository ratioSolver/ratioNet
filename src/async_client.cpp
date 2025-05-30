#include "async_client.hpp"
#include "logging.hpp"

namespace network
{
    async_client_base::async_client_base(std::string_view host, unsigned short port) : host(host), port(port), work_guard(asio::make_work_guard(io_ctx)), resolver(io_ctx), endpoints(resolver.resolve(host, std::to_string(port)))
    {
        io_thrd = std::thread([this]
                              { io_ctx.run(); });
    }

    void async_client_base::send(utils::u_ptr<request> req, std::function<void(const response &)> &&cb)
    {
        asio::post(io_ctx, [this, req = std::move(req), cb = std::move(cb)]() mutable
                   {
                       request_queue.emplace(std::move(req), std::move(cb));
                       if (!is_connected())
                           connect(endpoints); // Connect to the server if not already connected..
                       else if (request_queue.size() == 1)
                           write(request_queue.front().first->get_buffer()); // If this is the first request, start writing it..
                   });
    }

    void async_client_base::on_connect(const asio::error_code &ec, const asio::ip::tcp::endpoint &endpoint)
    {
        if (ec)
        {
            LOG_ERR("Failed to connect to " << endpoint << ": " << ec.message());
            return;
        }
        LOG_DEBUG("Connected to " << endpoint);
        if (!request_queue.empty())
            write(request_queue.front().first->get_buffer()); // Start writing the first request in the queue..
    }

    void async_client_base::on_write(const asio::error_code &ec, std::size_t bytes_transferred)
    {
        if (ec)
        {
            LOG_ERR("Failed to write: " << ec.message());
            return;
        }
        LOG_DEBUG("Wrote " << bytes_transferred << " bytes");
        auto &req = request_queue.front();
        request_queue.pop();
        if (!request_queue.empty()) // Write the next request in the queue..
            write(request_queue.front().first->get_buffer());
    }

    async_client::async_client(std::string_view host, unsigned short port) : async_client_base(host, port), socket(io_ctx) {}
    async_client::~async_client()
    {
        if (is_connected())
            disconnect();
        asio::error_code ec;
        if (ec && ec != asio::error::not_connected)
            LOG_ERR("Failed to disconnect: " << ec.message());
        work_guard.reset(); // Stop the io_context from running..
        if (io_thrd.joinable())
            io_thrd.join();
    }

    bool async_client::is_connected() const { return socket.is_open(); }
    void async_client::connect(const asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints)
    {
        for (const auto &endpoint : endpoints)
            LOG_DEBUG("Trying to connect to " << endpoint.endpoint());
        asio::async_connect(socket, endpoints, std::bind(&async_client::on_connect, this, std::placeholders::_1, std::placeholders::_2));
    }
    void async_client::disconnect()
    {
        asio::error_code ec;
        socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        if (ec && ec != asio::error::not_connected)
            LOG_ERR("Failed to disconnect: " << ec.message());
        socket.close(ec);
    }

    void async_client::write(asio::streambuf &buffer) { asio::async_write(socket, buffer, std::bind(&async_client::on_write, this, std::placeholders::_1, std::placeholders::_2)); }

#ifdef ENABLE_SSL
    async_ssl_client::async_ssl_client(std::string_view host, unsigned short port) : async_client_base(host, port), ssl_ctx(asio::ssl::context::TLS_VERSION), socket(io_ctx, ssl_ctx)
    {
        ssl_ctx.set_default_verify_paths();
        if (!SSL_set_tlsext_host_name(socket.native_handle(), host.data()))
        {
            LOG_ERR("SSL_set_tlsext_host_name failed");
            throw std::runtime_error("SSL_set_tlsext_host_name failed");
        }
    }
    async_ssl_client::~async_ssl_client()
    {
        if (is_connected())
            disconnect();
        asio::error_code ec;
        if (ec && ec != asio::error::not_connected)
            LOG_ERR("Failed to disconnect: " << ec.message());
        work_guard.reset(); // Stop the io_context from running..
        if (io_thrd.joinable())
            io_thrd.join();
    }

    bool async_ssl_client::is_connected() const { return socket.next_layer().is_open(); }
    void async_ssl_client::connect(const asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints)
    {
        for (const auto &endpoint : endpoints)
            LOG_DEBUG("Trying to connect to " << endpoint.endpoint());
        asio::async_connect(socket.next_layer(), endpoints, [this](const asio::error_code &ec, const asio::ip::tcp::endpoint &endpoint)
                            {
                                if (ec)
                                    return on_connect(ec, endpoint);
                                socket.async_handshake(asio::ssl::stream_base::client, [this, &endpoint](const asio::error_code &ec)
                                                       {
                                                           if (ec)
                                                           {
                                                               LOG_ERR("SSL handshake failed: " << ec.message());
                                                               return on_connect(ec, endpoint);
                                                           }
                                                           LOG_DEBUG("SSL handshake successful");
                                                           on_connect(ec, endpoint); }); });
    }
    void async_ssl_client::disconnect()
    {
        asio::error_code ec;
        socket.next_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        if (ec && ec != asio::error::not_connected)
            LOG_ERR("Failed to disconnect: " << ec.message());
        socket.next_layer().close(ec);
    }

    void async_ssl_client::write(asio::streambuf &buffer) { asio::async_write(socket, buffer, std::bind(&async_ssl_client::on_write, this, std::placeholders::_1, std::placeholders::_2)); }
#endif
} // namespace network
