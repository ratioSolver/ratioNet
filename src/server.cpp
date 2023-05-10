#include "server.h"
#include "http_session.h"
#include "logging.h"

namespace network
{
    server::server(const std::string &address, unsigned short port) : signals(io_context), acceptor(io_context), socket(io_context)
    {
        signals.add(SIGINT);
        signals.add(SIGTERM);
#if defined(SIGQUIT)
        signals.add(SIGQUIT);
#endif
        signals.async_wait([this](boost::system::error_code, int)
                           { stop(); });

        boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::make_address(address), port);
        boost::system::error_code ec;
        acceptor.open(boost::asio::ip::tcp::v4(), ec);
        if (ec)
        {
            LOG_ERR("Error opening acceptor: " << ec.message());
            return;
        }
        acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec);
        if (ec)
        {
            LOG_ERR("Error setting reuse_address: " << ec.message());
            return;
        }
        acceptor.bind(endpoint, ec);
        if (ec)
        {
            LOG_ERR("Error binding to " << endpoint << ": " << ec.message());
            return;
        }
        acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
        if (ec)
        {
            LOG_ERR("Error listening: " << ec.message());
            return;
        }
    }

    void server::start()
    {
        LOG("Starting server on " << acceptor.local_endpoint());
        acceptor.async_accept(socket, [this](boost::system::error_code ec)
                              { on_accept(ec); });
        io_context.run();
    }

    void server::stop()
    {
        io_context.stop();
        LOG("Server stopped.");
    }

    void server::on_accept(boost::system::error_code ec)
    {
        if (ec)
            return;

        (new http_session(*this, std::move(socket)))->run();

        acceptor.async_accept(socket, [this](boost::system::error_code ec)
                              { on_accept(ec); });
    }

} // namespace network