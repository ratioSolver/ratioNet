#include "http_session.h"

namespace network
{
    plain_http_session::plain_http_session(boost::beast::tcp_stream &&stream, boost::beast::flat_buffer &&buffer) : http_session(std::move(buffer)), stream(std::move(stream)) {}

    void plain_http_session::run() { do_read(); }
    void plain_http_session::close() { stream.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send); }

    ssl_http_session::ssl_http_session(boost::beast::tcp_stream &&stream, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&buffer) : http_session(std::move(buffer)), stream(std::move(stream), ctx) {}

    void ssl_http_session::run()
    {
        // Set the timeout.
        boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));

        // Perform the SSL handshake
        stream.async_handshake(boost::asio::ssl::stream_base::server, buffer.data(), [this](boost::system::error_code ec, size_t bytes_used)
                               { on_handshake(ec, bytes_used); });
    }

    void ssl_http_session::close()
    {
        // Set the timeout.
        boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));

        // Perform the SSL shutdown
        stream.async_shutdown([this](boost::system::error_code ec)
                              { on_shutdown(ec); });
    }

    void ssl_http_session::on_handshake(boost::system::error_code ec, size_t bytes_used)
    {
        if (ec)
        {
            LOG_ERR("SSL handshake failed: " << ec.message());
            delete this;
            return;
        }

        // Consume the portion of the buffer used by the handshake
        buffer.consume(bytes_used);

        do_read();
    }

    void ssl_http_session::on_shutdown(boost::system::error_code ec)
    {
        if (ec)
        {
            LOG_ERR("SSL shutdown failed: " << ec.message());
            delete this;
            return;
        }

        // At this point the connection is closed gracefully
    }
} // namespace network
