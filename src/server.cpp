#include "server.h"
#include "logging.h"

namespace network
{
    server::server(const std::string &address, unsigned short port, std::size_t concurrency_hint) : ioc(concurrency_hint), signals(ioc), endpoint(boost::asio::ip::make_address(address), port), acceptor(boost::asio::make_strand(ioc))
    {
        signals.add(SIGINT);
        signals.add(SIGTERM);
#if defined(SIGQUIT)
        signals.add(SIGQUIT);
#endif // defined(SIGQUIT)

        signals.async_wait([this](boost::system::error_code /*ec*/, int /*signo*/)
                           { ioc.stop(); });

        threads.reserve(concurrency_hint);
    }

    void server::start()
    {
        LOG("Starting server on " << endpoint);

        boost::system::error_code ec;
        acceptor.open(endpoint.protocol(), ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec);
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

        acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        acceptor.async_accept(boost::asio::make_strand(ioc), [this](boost::beast::error_code ec, boost::asio::ip::tcp::socket socket)
                              { on_accept(ec, std::move(socket)); });

        for (auto i = threads.size(); i > 0; --i)
            threads.emplace_back([this]
                                 { ioc.run(); });

        ioc.run();
    }

    void server::stop() {}

    void server::set_ssl_context(const std::string &certificate_chain_file, const std::string &private_key_file, const std::string &dh_file)
    {
        ctx.use_certificate_chain_file(certificate_chain_file);
        ctx.use_private_key_file(private_key_file, boost::asio::ssl::context::pem);
        ctx.use_tmp_dh_file(dh_file);
    }

    void server::on_accept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
        }
        else
        {
            LOG_DEBUG("Accepted connection from " << socket.remote_endpoint());
        }

        acceptor.async_accept(boost::asio::make_strand(ioc), [this](boost::beast::error_code ec, boost::asio::ip::tcp::socket socket)
                              { on_accept(ec, std::move(socket)); });
    }
} // namespace network
