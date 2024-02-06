#include "sync_server.hpp"

namespace network::sync
{
    server::server(const std::string &address, unsigned short port, std::size_t concurrency_hint) : network::server(address, port, concurrency_hint) {}

    void server::do_accept()
    {
        while (true)
        { // Accept a new connection
            boost::asio::ip::tcp::socket socket(io_ctx);
            acceptor.accept(socket);
#ifdef USE_SSL
            session_detector(*this, std::move(socket), ctx).run();
#else
            {
                boost::beast::tcp_stream stream(std::move(socket));
                boost::beast::flat_buffer buffer;
                sessions.emplace(std::make_unique<plain_session>(*this, std::move(stream), std::move(buffer))).first->get()->run();
            }
#endif
        }
    }

#ifdef USE_SSL
    void session_detector::run()
    {
        boost::beast::error_code ec;
        stream.expires_after(std::chrono::seconds(30));
        bool result = boost::beast::detect_ssl(stream, buffer, ec);
        if (ec)
            throw std::runtime_error(ec.message());
        else if (result)
            static_cast<server &>(srv).sessions.emplace(std::make_unique<ssl_session>(srv, std::move(stream), ctx, std::move(buffer))).first->get()->run();
        else
            static_cast<server &>(srv).sessions.emplace(std::make_unique<plain_session>(srv, std::move(stream), std::move(buffer))).first->get()->run();
    }
#endif

    void plain_session::run()
    {
        parser.emplace();                                                               // Construct a new parser for each message
        parser->body_limit(10000);                                                      // Set the limit on the allowed size of a message
        boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30)); // Set the timeout

        boost::beast::error_code ec;
        while (true)
        { // Read a message
            boost::beast::http::read(stream, buffer, *parser, ec);
            if (ec == boost::beast::http::error::end_of_stream)
                break;
            if (ec)
                throw std::runtime_error(ec.message());

            if (boost::beast::websocket::is_upgrade(parser->get()))
            {
                boost::beast::get_lowest_layer(stream).expires_never();
                auto req = parser->release();
                auto handler = get_ws_handler(req.target().to_string());
                // TODO: Create a websocket session
            }

            handle_request(parser->release()); // Handle the HTTP request
        }
    }
    void plain_session::do_eof()
    {
        boost::beast::error_code ec;
        stream.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    }

#ifdef USE_SSL
    void ssl_session::run()
    {
        boost::beast::error_code ec;
        boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));
        stream.handshake(boost::asio::ssl::stream_base::server, ec);
        if (ec)
            throw std::runtime_error(ec.message());
        while (true)
        { // Read a message
            boost::beast::http::read(stream, buffer, *parser, ec);
            if (ec == boost::beast::http::error::end_of_stream)
                return do_eof();
            else if (ec)
                throw std::runtime_error(ec.message());

            if (boost::beast::websocket::is_upgrade(parser->get()))
            {
                boost::beast::get_lowest_layer(stream).expires_never();
                auto req = parser->release();
                auto handler = get_wss_handler(req.target().to_string());
                // TODO: Create a websocket session
            }

            handle_request(parser->release()); // Handle the HTTP request
        }
    }
    void ssl_session::do_eof()
    {
        boost::beast::error_code ec;
        stream.shutdown(ec);
    }
#endif
} // namespace network