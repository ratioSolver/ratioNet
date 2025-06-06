#include "server.hpp"
#include "server_session.hpp"
#include "logging.hpp"

namespace network
{
    server_base::server_base(std::string_view host, unsigned short port, std::size_t concurrency_hint) : io_ctx(static_cast<int>(concurrency_hint)), signals(io_ctx, SIGINT, SIGTERM), endpoint(asio::ip::make_address(host), port), acceptor(asio::make_strand(io_ctx))
    {
        threads.reserve(concurrency_hint);
        signals.async_wait([this](const std::error_code &ec, [[maybe_unused]] int signal)
                           {
                               if (!ec)
                               {
                                   LOG_DEBUG("Received signal " + std::to_string(signal));
                                   stop();
                               } });
    }

    server_base::~server_base() { stop(); }

    void server_base::start()
    {
        LOG_DEBUG("Starting server on " + endpoint.address().to_string() + ":" + std::to_string(endpoint.port()));

        std::error_code ec;
        acceptor.open(endpoint.protocol(), ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
        acceptor.set_option(asio::socket_base::reuse_address(true), ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
        acceptor.bind(endpoint, ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
        acceptor.listen(asio::socket_base::max_listen_connections, ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        do_accept();

        for (auto i = threads.capacity(); i > 0; --i)
            threads.emplace_back([this]
                                 { io_ctx.run(); });

        io_ctx.run();
    }

    void server_base::do_accept() { acceptor.async_accept(asio::make_strand(io_ctx), std::bind(&server_base::on_accept, this, asio::placeholders::error, std::placeholders::_2)); }

    server::server(std::string_view host, unsigned short port, std::size_t concurrency_hint) : server_base(host, port, concurrency_hint) {}

    void server::on_accept(const std::error_code &ec, asio::ip::tcp::socket socket)
    {
        if (!ec)
            std::make_shared<server_session>(*this, std::move(socket))->run();
        else
            LOG_ERR("Accept error: " + ec.message());
        do_accept();
    }

#ifdef ENABLE_SSL
    ssl_server::ssl_server(std::string_view host, unsigned short port, std::size_t concurrency_hint) : server_base(host, port, concurrency_hint), ssl_ctx(asio::ssl::context::TLS_VERSION) {}

    void ssl_server::on_accept(const std::error_code &ec, asio::ip::tcp::socket socket)
    {
        if (!ec)
        {
            auto session = std::make_shared<ssl_server_session>(*this, asio::ssl::stream<asio::ip::tcp::socket>(std::move(socket), ssl_ctx));
            session->handshake([this, session](const std::error_code &ec)
                               {
                                   if (!ec)
                                       session->run();
                                   else
                                       LOG_ERR("SSL Handshake error: " + ec.message()); });
        }
        else
            LOG_ERR("SSL Accept error: " + ec.message());
        do_accept();
    }
#endif
} // namespace network