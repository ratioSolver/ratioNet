#include "base_server.hpp"
#include <boost/beast.hpp>

namespace network
{
    base_server::base_server(const std::string &address, const std::string &port, std::size_t concurrency_hint) : io_ctx(concurrency_hint), signals(io_ctx), endpoint(boost::asio::ip::make_address(address), std::stoi(port)), acceptor(boost::asio::make_strand(io_ctx))
    {
        signals.add(SIGINT);
        signals.add(SIGTERM);
#if defined(SIGQUIT)
        signals.add(SIGQUIT);
#endif // defined(SIGQUIT)

        signals.async_wait([this](boost::beast::error_code const &ec, int)
                           {
                            if (ec)
                                return error_handler(ec.message());
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

        for (std::size_t i = 0; i < threads.capacity(); ++i)
            threads.emplace_back([this]
                                 { io_ctx.run(); });

        io_ctx.run();
    }

    void base_server::stop()
    {
        io_ctx.stop();
        for (auto &thread : threads)
            thread.join();
    }

    websocket_handler &base_server::ws(const std::string &target)
    {
        ws_routes.emplace_back(std::regex(target), std::make_unique<websocket_handler>());
        return *ws_routes.back().second;
    }

#ifdef USE_SSL
    void base_server::set_ssl_context(const std::string &cert_chain_file, const std::string &private_key_file, const std::string &tmp_dh_file)
    {
        ssl_ctx.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::no_sslv3 | boost::asio::ssl::context::single_dh_use);
        ssl_ctx.use_certificate_chain_file(cert_chain_file);
        ssl_ctx.use_private_key_file(private_key_file, boost::asio::ssl::context::pem);
        ssl_ctx.use_tmp_dh_file(tmp_dh_file);
    }

    websocket_handler &base_server::wss(const std::string &target)
    {
        wss_routes.emplace_back(std::regex(target), std::make_unique<websocket_handler>());
        return *wss_routes.back().second;
    }
#endif

    boost::optional<http_handler &> base_server::get_http_handler(boost::beast::http::verb method, const std::string &target)
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

#ifdef USE_SSL
    boost::optional<http_handler &> base_server::get_https_handler(boost::beast::http::verb method, const std::string &target)
    {
        for (auto &handler : https_routes[method])
            if (std::regex_match(target, handler.first))
                return *handler.second;
        return boost::none;
    }
    boost::optional<websocket_handler &> base_server::get_wss_handler(const std::string &target)
    {
        for (auto &handler : wss_routes)
            if (std::regex_match(target, handler.first))
                return *handler.second;
        return boost::none;
    }
#endif

    std::map<std::string, std::string> base_server::parse_query(const std::string &query)
    {
        std::map<std::string, std::string> params;

        std::string::size_type pos = 0;
        while (pos < query.size())
        {
            std::string::size_type next = query.find('&', pos);
            std::string::size_type eq = query.find('=', pos);
            if (eq == std::string::npos)
                break;
            if (next == std::string::npos)
                next = query.size();
            params.emplace(query.substr(pos, eq - pos), query.substr(eq + 1, next - eq - 1));
            pos = next + 1;
        }

        return params;
    }
} // namespace network