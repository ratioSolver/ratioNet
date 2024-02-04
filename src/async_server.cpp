#include <boost/beast.hpp>
#include "async_server.hpp"

namespace network::async
{
    server::server(const std::string &address, unsigned short port, std::size_t concurrency_hint) : network::server(address, port, concurrency_hint) {}

    void server::do_accept() { acceptor.async_accept(boost::asio::make_strand(io_ctx), boost::beast::bind_front_handler(&server::on_accept, this)); }

    void server::on_accept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket)
    {
        if (ec)
            throw std::runtime_error(ec.message());
        else
#ifdef USE_SSL
            std::make_shared<session_detector>(*this, std::move(socket), ctx)->run();
#else
        {
            boost::beast::tcp_stream stream(std::move(socket));
            boost::beast::flat_buffer buffer;
            std::make_shared<plain_session>(*this, std::move(stream), std::move(buffer))->run();
        }
#endif
        do_accept(); // Accept another connection
    }

#ifdef USE_SSL
    void session_detector::run() { boost::asio::dispatch(stream.get_executor(), boost::beast::bind_front_handler(&session_detector::on_run, shared_from_this())); }
    void session_detector::on_run()
    {
        stream.expires_after(std::chrono::seconds(30));                                                                                     // Set the timeout
        boost::beast::async_detect_ssl(stream, buffer, boost::beast::bind_front_handler(&session_detector::on_detect, shared_from_this())); // Detect SSL
    }
    void session_detector::on_detect(boost::beast::error_code ec, bool result)
    {
        if (ec)
            throw std::runtime_error(ec.message());
        else if (result)
            std::make_shared<ssl_session>(srv, std::move(stream), ctx, std::move(buffer))->run();
        else
            std::make_shared<plain_session>(srv, std::move(stream), std::move(buffer))->run();
    }
#endif

    void plain_session::run()
    { // Start reading
        do_read();
    }
    void plain_session::do_eof()
    {
        boost::beast::error_code ec;
        stream.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    }

    void plain_session::do_read()
    {
        parser.emplace();                                                               // Construct a new parser for each message
        parser->body_limit(10000);                                                      // Set the limit on the allowed size of a message
        boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30)); // Set the timeout

        boost::beast::http::async_read(stream, buffer, *parser, boost::beast::bind_front_handler(&plain_session::on_read, this->shared_from_this())); // Read a request
    }

#ifdef USE_SSL
    void ssl_session::run()
    {
        boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));
        stream.async_handshake(boost::asio::ssl::stream_base::server, buffer.data(), boost::beast::bind_front_handler(&ssl_session::on_handshake, this->shared_from_this()));
    }
    void ssl_session::do_eof()
    {
        boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));
        stream.async_shutdown(boost::beast::bind_front_handler(&ssl_session::on_shutdown, this->shared_from_this()));
    }

    void ssl_session::on_handshake(boost::beast::error_code ec, std::size_t bytes_used)
    {
        if (ec)
            throw std::runtime_error(ec.message());
        else
        {
            buffer.consume(bytes_used); // Consume the handshake buffer
            do_read();
        }
    }

    void ssl_session::on_shutdown(boost::beast::error_code ec)
    {
        if (ec)
            throw std::runtime_error(ec.message());
    }

    void ssl_session::do_read()
    {
        parser.emplace();                                                               // Construct a new parser for each message
        parser->body_limit(10000);                                                      // Set the limit on the allowed size of a message
        boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30)); // Set the timeout

        boost::beast::http::async_read(stream, buffer, *parser, boost::beast::bind_front_handler(&ssl_session::on_read, this->shared_from_this())); // Read a request
    }
#endif
} // namespace network