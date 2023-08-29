#include "http_session.h"
#include "logging.h"

namespace network
{
    http_session::http_session(server &srv, boost::beast::tcp_stream &&stream, boost::beast::flat_buffer &&buffer, size_t queue_limit) : srv(srv), stream(std::move(stream)), buffer(std::move(buffer)), queue_limit(queue_limit) { do_read(); }

    void http_session::do_read()
    {
        parser.emplace();                                                               // Construct a new parser for each message
        parser->body_limit(10000);                                                      // Set the limit on the allowed size of a message
        boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30)); // Set the timeout

        boost::beast::http::async_read(stream, buffer, *parser, [this](boost::beast::error_code ec, std::size_t bytes_transferred)
                                       { on_read(ec, bytes_transferred); }); // Read a request
    }

    void http_session::on_read(boost::beast::error_code ec, std::size_t)
    {
        if (ec == boost::beast::http::error::end_of_stream)
            return do_eof();

        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        work_queue.emplace(new http_work_impl(*this, parser->release()));
    }

    void http_session::on_write(boost::beast::error_code ec, std::size_t, bool close)
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

    void http_session::do_eof()
    {
        boost::beast::error_code ec;
        stream.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
        delete this; // Delete this session
    }
} // namespace network