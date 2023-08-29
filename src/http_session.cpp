#include "http_session.h"

namespace network
{
    http_session::http_session(server &srv, boost::beast::tcp_stream &&stream, boost::beast::flat_buffer &&buffer) : srv(srv), stream(std::move(stream)), buffer(std::move(buffer)) { do_read(); }

    void http_session::do_read()
    {
        parser.emplace();                                                               // Construct a new parser for each message
        parser->body_limit(10000);                                                      // Set the limit on the allowed size of a message
        boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30)); // Set the timeout
    }

    void http_session::do_eof()
    {
        boost::beast::error_code ec;
        stream.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
        delete this; // Delete this session
    }
} // namespace network