#include "server.hpp"
#include <boost/beast.hpp>

namespace network
{
    server::server(const std::string &address, unsigned short port, std::size_t concurrency_hint) : io_ctx(concurrency_hint), signals(io_ctx), endpoint(boost::asio::ip::make_address(address), port), acceptor(boost::asio::make_strand(io_ctx))
    {
        signals.add(SIGINT);
        signals.add(SIGTERM);
#if defined(SIGQUIT)
        signals.add(SIGQUIT);
#endif // defined(SIGQUIT)

        threads.reserve(concurrency_hint);
    }

    void server::start()
    {
        boost::beast::error_code ec;
        acceptor.open(endpoint.protocol(), ec);
        if (ec)
            return;

        acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec);
        if (ec)
            return;

        acceptor.bind(endpoint, ec);
        if (ec)
            return;

        acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
        if (ec)
            return;

        do_accept();

        for (std::size_t i = 0; i < threads.capacity(); ++i)
            threads.emplace_back([this]
                                 { io_ctx.run(); });

        io_ctx.run();
    }

    void server::stop()
    {
        io_ctx.stop();
        for (auto &thread : threads)
            thread.join();
    }

    std::map<std::string, std::string> server::parse_query(const std::string &query)
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