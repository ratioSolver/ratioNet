#include "server.h"
#include "logging.h"

namespace network
{
    server::server(const std::string &address, unsigned short port, std::size_t thread_pool_size) : thread_pool_size(thread_pool_size), ioc(thread_pool_size), signals(ioc), acceptor(ioc)
    {
        signals.add(SIGINT);
        signals.add(SIGTERM);
#if defined(SIGQUIT)
        signals.add(SIGQUIT);
#endif // defined(SIGQUIT)

        signals.async_wait([this](boost::system::error_code, int)
                           { stop(); });

        boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::make_address(address), port);
        boost::system::error_code ec;
        acceptor.open(endpoint.protocol(), ec);
        if (ec)
        {
            LOG_ERR("Error opening acceptor: " << ec.message());
            return;
        }
        acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec);
        if (ec)
        {
            LOG_ERR("Error setting acceptor option: " << ec.message());
            return;
        }
        acceptor.bind(endpoint, ec);
        if (ec)
        {
            LOG_ERR("Error binding to address " << endpoint << ": " << ec.message());
            return;
        }
        acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
        if (ec)
        {
            LOG_ERR("Error listening on socket: " << ec.message());
            return;
        }
    }

    void server::start()
    {
        LOG("Starting server on " << acceptor.local_endpoint());
        acceptor.async_accept([this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket)
                              { on_accept(ec, std::move(socket)); });

        for (std::size_t i = 0; i < thread_pool_size; ++i)
            threads.emplace_back([this]
                                 { ioc.run(); });
        ioc.run();
    }

    void server::stop()
    {
        LOG("Stopping server");
        acceptor.close();

        ioc.stop();

        for (auto &thread : threads)
            thread.join();
    }

    void server::on_accept(boost::system::error_code ec, boost::asio::ip::tcp::socket socket)
    {
        if (ec)
        {
            LOG_ERR("Error accepting connection: " << ec.message());
            return;
        }

        LOG_DEBUG("Accepted connection from " << socket.remote_endpoint());
        acceptor.async_accept([this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket)
                              { on_accept(ec, std::move(socket)); });
    }
} // namespace network
