#include "http_session.hpp"
#include "server.hpp"

namespace network
{
    base_http_session::base_http_session(base_server &srv) : srv(srv) {}

    void base_http_session::fire_on_error(const boost::beast::error_code &ec) { srv.error_handler(ec.message()); }

    http_session::http_session(base_server &srv, boost::asio::ip::tcp::socket &&socket) : base_http_session(srv), stream(std::move(socket)) {}

    void http_session::run() { do_read(); }

    void http_session::do_eof()
    {
        boost::beast::error_code ec;
        stream.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    }

    void http_session::do_read()
    {
        parser.emplace();                                                               // Construct a new parser for each message
        parser->body_limit(10000);                                                      // Set the limit on the allowed size of a message
        boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30)); // Set the timeout

        boost::beast::http::async_read(stream, buffer, *parser, boost::beast::bind_front_handler(&http_session::on_read, shared_from_this()));
    }

    void http_session::on_read(boost::beast::error_code ec, std::size_t)
    {
        if (ec == boost::beast::http::error::end_of_stream)
            return do_eof();

        if (ec)
            return fire_on_error(ec);

        do_read();
    }
} // namespace network
