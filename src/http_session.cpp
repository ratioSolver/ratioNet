#include "http_session.h"

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
} // namespace network
