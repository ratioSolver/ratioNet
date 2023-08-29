#include "ssl_http_session.h"
#include "server.h"
#include "logging.h"

namespace network
{
    ssl_http_session::ssl_http_session(server &srv, boost::beast::tcp_stream &&stream, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&buffer, size_t queue_limit) : srv(srv), stream(std::move(stream), ctx), buffer(std::move(buffer)), queue_limit(queue_limit)
    {
        boost::beast::get_lowest_layer(this->stream).expires_after(std::chrono::seconds(30)); // Set the timeout
        this->stream.async_handshake(boost::asio::ssl::stream_base::server, buffer.data(), [this](boost::beast::error_code ec, std::size_t)
                                     { on_handshake(ec); }); // Perform the SSL handshake
    }

    void ssl_http_session::on_handshake(boost::beast::error_code ec)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            delete this;
        }
        else
        {
            buffer.consume(buffer.size()); // Consume the portion of the buffer used by the handshake

            do_read();
        }
    }

    void ssl_http_session::do_read()
    {
        parser.emplace();                                                               // Construct a new parser for each message
        parser->body_limit(10000);                                                      // Set the limit on the allowed size of a message
        boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30)); // Set the timeout

        boost::beast::http::async_read(stream, buffer, *parser, [this](boost::beast::error_code ec, std::size_t bytes_transferred)
                                       { on_read(ec, bytes_transferred); }); // Read a request
    }

    void ssl_http_session::on_read(boost::beast::error_code ec, std::size_t)
    {
        if (ec == boost::beast::http::error::end_of_stream)
            return do_eof();

        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        work_queue.emplace(new request_handler_impl(*this, parser->release())); // Send the request to the queue
    }

    void ssl_http_session::on_write(boost::beast::error_code ec, std::size_t, bool close)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        if (close)
        { // This means we should close the connection, usually because the response indicated the "Connection: close" semantic.
            return do_eof();
        }
    }

    void ssl_http_session::do_eof()
    {
        boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30)); // Set the timeout
        stream.async_shutdown([this](boost::beast::error_code ec)
                              { on_shutdown(ec); }); // Perform the SSL shutdown
    }

    void ssl_http_session::on_shutdown(boost::beast::error_code ec)
    {
        if (ec)
            LOG_ERR(ec.message());
        else
            LOG_DEBUG("SSL shutdown");
        delete this; // Delete this session
    }
} // namespace network