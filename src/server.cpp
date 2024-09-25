#include "server.hpp"
#include "logging.hpp"
#ifdef _WIN32
// Windows-specific code
#define SIGQUIT 3 // Define a dummy value for SIGQUIT on Windows if necessary
#endif
#include <csignal>

namespace network
{
    server::server(const std::string &host, unsigned short port, std::size_t concurrency_hint) : io_ctx(concurrency_hint), signals(io_ctx, SIGINT, SIGTERM, SIGQUIT), endpoint(asio::ip::make_address(host), port), acceptor(asio::make_strand(io_ctx))
    {
        threads.reserve(concurrency_hint);
        signals.async_wait([this](const std::error_code &ec, int signal)
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

    void server::handle_request(session &s, std::unique_ptr<request> req)
    {
        // read next request if connection is keep-alive
        if (req->is_keep_alive())
            s.read(); // read next request

        if (auto it = routes.find(req->get_verb()); it != routes.end())
            for (const auto &r : it->second)
                if (std::regex_match(req->get_target(), r.get_path()))
                {
                    try
                    {
                        // call the route handler
                        auto res = r.get_handler()(*req);
                        s.enqueue(std::move(res));
                    }
                    catch (const std::exception &e)
                    {
                        LOG_ERR(e.what());
                        auto res = std::make_unique<json_response>(json::json{{"message", "Internal Server Error"}}, status_code::internal_server_error);
                        s.enqueue(std::move(res));
                    }
                    return;
                }

        LOG_WARN("No route for " + req->get_target());
        json::json msg = {{"message", "Not Found"}};
        auto res = std::make_unique<json_response>(json::json(msg), status_code::not_found);
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

    void server::on_message(ws_session &s, std::unique_ptr<message> msg)
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