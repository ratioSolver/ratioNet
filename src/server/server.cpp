#include "server.hpp"
#include "server_session.hpp"
#include "ws_server_session.hpp"
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

    server_base::~server_base()
    {
        if (acceptor.is_open())
            stop();
    }

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

    void server_base::stop()
    {
        LOG_DEBUG("Stopping server");
        acceptor.close();
        io_ctx.stop();
        for (auto &thread : threads)
            thread.join();
    }

    void server_base::add_route(verb v, std::string_view path, std::function<std::unique_ptr<response>(request &)> &&handler) noexcept
    {
        routes[v].emplace_back(path, std::move(handler));
        for (auto &m : middlewares)
            m->added_route(v, routes[v].back());
        LOG_DEBUG("Added route: " + std::string(path) + " for verb: " + to_string(v));
    }

    void server_base::do_accept() { acceptor.async_accept(asio::make_strand(io_ctx), std::bind(&server_base::on_accept, this, asio::placeholders::error, std::placeholders::_2)); }

    void server_base::handle_request(server_session_base &s, request &req)
    {
        if (auto it = routes.find(req.get_verb()); it != routes.end())
            for (const auto &r : it->second)
                if (r.match(req.get_target()))
                {
                    try
                    {
                        for (auto &m : middlewares)
                            m->before_request(req);
                        // call the route handler
                        auto res = r.get_handler()(req);
                        for (auto &m : middlewares)
                            m->after_request(req, *res);
                        s.enqueue(std::move(res));
                    }
                    catch (const std::exception &e)
                    {
                        LOG_ERR(e.what());
                        s.enqueue(std::make_unique<json_response>(json::json{{"message", "Internal Server Error"}}, status_code::internal_server_error));
                    }
                    return;
                }

        LOG_WARN("No route for " + req.get_target());
        json::json msg = {{"message", "Not Found"}};
        s.enqueue(std::make_unique<json_response>(json::json(msg), status_code::not_found));
    }

    void server_base::on_connect(ws_server_session_base &s)
    {
        if (auto it = ws_routes.find(s.path); it != ws_routes.end())
            it->second.on_open_handler(s);
        else
            LOG_WARN("No route for " + s.path);
    }
    void server_base::on_disconnect(ws_server_session_base &s)
    {
        if (auto it = ws_routes.find(s.path); it != ws_routes.end())
            it->second.on_close_handler(s);
        else
            LOG_WARN("No route for " + s.path);
    }
    void server_base::on_message(ws_server_session_base &s, const message &msg)
    {
        switch (msg.get_fin_rsv_opcode() & 0x0F)
        {
        case 0x00: // continuation
        case 0x01: // text
        case 0x02: // binary
            if (auto it = ws_routes.find(s.path); it != ws_routes.end())
                it->second.on_message_handler(s, msg);
            else
                LOG_WARN("No route for " + s.path);
            break;
        case 0x08: // close
            s.close();
            break;
        case 0x09: // ping
            s.pong();
            break;
        case 0x0A: // pong
            break;
        default:
            LOG_ERR("Unknown opcode");
        }
    }
    void server_base::on_error(ws_server_session_base &s, const std::error_code &ec)
    {
        if (auto it = ws_routes.find(s.path); it != ws_routes.end())
            it->second.on_error_handler(s, ec);
        else
            LOG_WARN("No route for " + s.path + " - Error: " + ec.message());
    }

    server::server(std::string_view host, unsigned short port, std::size_t concurrency_hint) : server_base(host, port, concurrency_hint) {}

    void server::on_accept(const std::error_code &ec, asio::ip::tcp::socket socket)
    {
        if (ec)
            LOG_ERR("Accept error: " + ec.message());
        else
        {
            LOG_DEBUG("Accepted connection from " + socket.remote_endpoint().address().to_string() + ":" + std::to_string(socket.remote_endpoint().port()));
            std::make_shared<server_session>(*this, std::move(socket))->run();
        }
        do_accept();
    }

#ifdef ENABLE_SSL
    ssl_server::ssl_server(std::string_view host, unsigned short port, std::size_t concurrency_hint) : server_base(host, port, concurrency_hint), ssl_ctx(asio::ssl::context::TLS_VERSION) {}

    void ssl_server::load_certificate(std::string_view cert_file, std::string_view key_file)
    {
        LOG_DEBUG("Loading certificate: " + std::string(cert_file));
        ssl_ctx.use_certificate_chain_file(cert_file.data());
        LOG_DEBUG("Loading private key: " + std::string(key_file));
        ssl_ctx.use_private_key_file(key_file.data(), asio::ssl::context::pem);
    }

    void ssl_server::on_accept(const std::error_code &ec, asio::ip::tcp::socket socket)
    {
        if (ec)
            LOG_ERR("SSL Accept error: " + ec.message());
        else
        {
            auto session = std::make_shared<ssl_server_session>(*this, asio::ssl::stream<asio::ip::tcp::socket>(std::move(socket), ssl_ctx));
            session->handshake([this, session](const std::error_code &ec)
                               {
                                   if (ec)
                                       LOG_ERR("SSL Handshake error: " + ec.message());
                                   else
                                       session->run(); });
        }
        do_accept();
    }
#endif
} // namespace network