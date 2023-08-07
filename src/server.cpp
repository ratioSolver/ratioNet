#include "server.h"
#include <boost/asio/dispatch.hpp>
#include <boost/asio/ssl.hpp>

namespace network
{
    detector::detector(boost::asio::ip::tcp::socket &&socket, boost::asio::ssl::context &ctx) : stream(std::move(socket)), ctx(ctx) {}

    void detector::run()
    {
        boost::asio::dispatch(stream.get_executor(), [this]()
                              { on_run(); });
    }

    void detector::on_run()
    {
        boost::beast::async_detect_ssl(stream, buffer, [this](boost::system::error_code ec, bool result)
                                       { on_detect(ec, result); });
    }

    void detector::on_detect(boost::system::error_code ec, bool result)
    {
        if (ec)
        {
            LOG_ERR("Error: " << ec.message() << "\n");
            return;
        }

        if (result)
            (new ssl_http_session(std::move(stream), ctx, std::move(buffer)))->run();
        else
            (new plain_http_session(std::move(stream), std::move(buffer)))->run();
    }

    server::server(boost::asio::io_context &ioc, boost::asio::ip::tcp::endpoint endpoint) : ioc(ioc), acceptor(ioc, endpoint), socket(ioc)
    {
    }

    void server::run() { do_accept(); }

    void server::do_accept()
    {
        acceptor.async_accept(socket, [this](boost::system::error_code ec)
                              { on_accept(ec); });
    }

    void server::on_accept(boost::system::error_code ec)
    {
        if (ec)
        {
            LOG_ERR("Error: " << ec.message() << "\n");
            return;
        }

        do_accept();
    }
} // namespace network
