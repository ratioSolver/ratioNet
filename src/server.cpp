#include "server.hpp"

namespace network
{
    base_server::base_server(const std::string &address, const std::string &port, std::size_t concurrency_hint) : io_ctx(concurrency_hint), signals(io_ctx), endpoint(boost::asio::ip::make_address(address), std::stoi(port)), acceptor(boost::asio::make_strand(io_ctx))
    {
        signals.add(SIGINT);
        signals.add(SIGTERM);
#if defined(SIGQUIT)
        signals.add(SIGQUIT);
#endif // defined(SIGQUIT)

        signals.async_wait([this](boost::beast::error_code ec, [[maybe_unused]] int signo)
                           {
                            log_handler("Received signal " + std::to_string(signo));
                            if (ec)
                            {
                                error_handler("signals: " + ec.message());
                                return;
                            }
                            
                            stop(); });

        threads.reserve(concurrency_hint);
    }

    void base_server::start()
    {
        log_handler("Starting server on " + endpoint.address().to_string() + ":" + std::to_string(endpoint.port()));

        boost::beast::error_code ec;
        acceptor.open(endpoint.protocol(), ec);
        if (ec)
            return error_handler(ec.message());

        acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec);
        if (ec)
            return error_handler(ec.message());

        acceptor.bind(endpoint, ec);
        if (ec)
            return error_handler(ec.message());

        acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
        if (ec)
            return error_handler(ec.message());

        do_accept();

        for (auto i = threads.capacity(); i > 0; --i)
            threads.emplace_back([this]
                                 { io_ctx.run(); });

        io_ctx.run();
    }

    void base_server::stop()
    {
        log_handler("Stopping server");
        io_ctx.stop();
        for (auto &thread : threads)
            thread.join();
    }

    boost::optional<base_http_handler &> base_server::get_http_handler(boost::beast::http::verb method, const std::string &target)
    {
        for (auto &handler : http_routes[method])
            if (std::regex_match(target, handler.first))
                return *handler.second;
        return boost::none;
    }
    boost::optional<websocket_handler &> base_server::get_ws_handler(const std::string &target)
    {
        for (auto &handler : ws_routes)
            if (std::regex_match(target, handler.first))
                return *handler.second;
        return boost::none;
    }

    void base_server::do_accept() { acceptor.async_accept(boost::asio::make_strand(io_ctx), boost::beast::bind_front_handler(&server::on_accept, this)); }

    void base_server::on_accept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket)
    {
        if (ec)
            error_handler(ec.message());
        else
        {
            log_handler("Accepted connection from " + socket.remote_endpoint().address().to_string() + ":" + std::to_string(socket.remote_endpoint().port()));
            std::make_shared<http_session>(*this, std::move(socket))->run();
        }

        do_accept();
    }

    server::server(const std::string &address, const std::string &port, std::size_t concurrency_hint) : base_server(address, port, concurrency_hint) {}
} // namespace network
