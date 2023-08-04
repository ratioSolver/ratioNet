#include "server.h"
#include <boost/asio/dispatch.hpp>
#include <boost/asio/ssl.hpp>

namespace network
{
    plain_http_session::plain_http_session(boost::beast::tcp_stream &&stream, boost::beast::flat_buffer &&buffer) : http_session(std::move(buffer)), stream(std::move(stream)) {}

    void plain_http_session::run() { do_read(); }

    void plain_http_session::do_eof()
    {
        stream.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send);
        delete this;
    }

    ssl_http_session::ssl_http_session(boost::beast::tcp_stream &&stream, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&buffer) : http_session(std::move(buffer)), stream(std::move(stream), ctx) {}

    void ssl_http_session::run()
    {
        boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));

        stream.async_handshake(boost::asio::ssl::stream_base::server, buffer.data(), [this](boost::system::error_code ec, size_t bytes_transferred)
                               { on_handshake(ec, bytes_transferred); });
    }

    void ssl_http_session::do_eof()
    {
        stream.async_shutdown([this](boost::system::error_code ec)
                              { on_shutdown(ec); });
    }

    void ssl_http_session::on_handshake(boost::system::error_code ec, size_t bytes_transferred)
    {
        if (ec)
        {
            LOG_ERR("Error: " << ec.message() << "\n");
            return;
        }

        buffer.consume(bytes_transferred);

        do_read();
    }

    void ssl_http_session::on_shutdown(boost::system::error_code ec)
    {
        if (ec)
        {
            LOG_ERR("Error: " << ec.message() << "\n");
            delete this;
            return;
        }
    }

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
