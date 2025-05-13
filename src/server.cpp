#include "server.hpp"
#include "middleware.hpp"
#include "logging.hpp"

namespace network
{
    server::server(std::string_view host, unsigned short port, std::size_t concurrency_hint) : io_ctx(static_cast<int>(concurrency_hint)), signals(io_ctx, SIGINT, SIGTERM), endpoint(asio::ip::make_address(host), port), acceptor(asio::make_strand(io_ctx))
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
    server::~server()
    {
        if (running)
            stop();
    }

    void server::start()
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

        running = true;
        do_accept();

        for (auto i = threads.capacity(); i > 0; --i)
            threads.emplace_back([this]
                                 { io_ctx.run(); });

        io_ctx.run();
    }

    void server::stop()
    {
        LOG_DEBUG("Stopping server");
        io_ctx.stop();
        for (auto &thread : threads)
            thread.join();
        running = false;
    }

    void server::add_route(verb v, std::string_view path, std::function<utils::u_ptr<response>(request &)> &&handler) noexcept
    {
        routes[v].emplace_back(path, std::move(handler));
        for (auto &m : middlewares)
            m->added_route(v, routes[v].back());
        LOG_DEBUG("Added route: " + std::string(path) + " for verb: " + to_string(v));
    }

#ifdef ENABLE_SSL
    void server::load_certificate(std::string_view cert_file, std::string_view key_file)
    {
        LOG_DEBUG("Loading certificate: " + std::string(cert_file));
        ctx.use_certificate_chain_file(cert_file.data());
        LOG_DEBUG("Loading private key: " + std::string(key_file));
        ctx.use_private_key_file(key_file.data(), asio::ssl::context::pem);
    }
#endif

    void server::do_accept() { acceptor.async_accept(asio::make_strand(io_ctx), std::bind(&server::on_accept, this, asio::placeholders::error, std::placeholders::_2)); }

    void server::on_accept(const std::error_code &ec, asio::ip::tcp::socket socket)
    {
        if (!ec)
#ifdef ENABLE_SSL
            std::make_shared<session>(*this, asio::ssl::stream<asio::ip::tcp::socket>(std::move(socket), ctx))->handshake();
#else
            std::make_shared<session>(*this, std::move(socket))->read();
#endif
        do_accept();
    }

    void server::handle_request(session &s, utils::u_ptr<request> req)
    {
        // read next request if connection is keep-alive
        if (req->is_keep_alive())
            s.read(); // read next request

        if (auto it = routes.find(req->get_verb()); it != routes.end())
            for (const auto &r : it->second)
                if (r.match(req->get_target()))
                {
                    try
                    {
                        for (auto &m : middlewares)
                            m->before_request(*req);
                        // call the route handler
                        auto res = r.get_handler()(*req);
                        for (auto &m : middlewares)
                            m->after_request(*req, *res);
                        s.enqueue(std::move(res));
                    }
                    catch (const std::exception &e)
                    {
                        LOG_ERR(e.what());
                        auto res = utils::make_u_ptr<json_response>(json::json{{"message", "Internal Server Error"}}, status_code::internal_server_error);
                        s.enqueue(std::move(res));
                    }
                    return;
                }

        LOG_WARN("No route for " + req->get_target());
        json::json msg = {{"message", "Not Found"}};
        auto res = utils::make_u_ptr<json_response>(json::json(msg), status_code::not_found);
        s.enqueue(std::move(res));
    }

    void server::on_connect(ws_session &s)
    {
        if (auto it = ws_routes.find(s.path); it != ws_routes.end())
            it->second.on_open_handler(s);
        else
            LOG_WARN("No route for " + s.path);
    }
    void server::on_disconnect(ws_session &s)
    {
        if (auto it = ws_routes.find(s.path); it != ws_routes.end())
            it->second.on_close_handler(s);
        else
            LOG_WARN("No route for " + s.path);
    }

    void server::on_message(ws_session &s, utils::u_ptr<message> msg)
    {
        switch (msg->get_fin_rsv_opcode() & 0x0F)
        {
        case 0x00: // continuation
        case 0x01: // text
        case 0x02: // binary
            if (auto it = ws_routes.find(s.path); it != ws_routes.end())
                it->second.on_message_handler(s, msg->get_payload());
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

    void server::on_error(ws_session &s, const std::error_code &ec)
    {
        if (auto it = ws_routes.find(s.path); it != ws_routes.end())
            it->second.on_error_handler(s, ec);
        else
            LOG_WARN("No route for " + s.path);
    }
} // namespace network