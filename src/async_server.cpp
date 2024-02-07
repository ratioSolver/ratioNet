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

    void plain_session::run() { do_read(); }
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

    void plain_session::on_read(boost::beast::error_code ec, std::size_t)
    {
        if (ec == boost::beast::http::error::end_of_stream)
            return do_eof();
        else if (ec)
            throw std::runtime_error(ec.message());

        if (boost::beast::websocket::is_upgrade(parser->get()))
        {
            boost::beast::get_lowest_layer(stream).expires_never();
            auto req = parser->release();
            auto handler = get_ws_handler(req.target().to_string());
            if (handler)
                std::make_shared<plain_websocket_session>(srv, std::move(stream), handler.value())->do_accept(std::move(req));
        }

        handle_request(parser->release()); // Handle the HTTP request
    }

    void plain_session::on_write(bool keep_alive, boost::beast::error_code ec, std::size_t)
    {
        if (ec)
            throw std::runtime_error(ec.message());

        if (!keep_alive) // This means we should close the connection, usually because the response indicated the "Connection: close" semantic.
            return do_eof();

        response_queue.pop();

        do_read();
    }

    void plain_websocket_session::send(const std::shared_ptr<const std::string> &msg) { boost::asio::post(websocket.get_executor(), boost::beast::bind_front_handler(&plain_websocket_session::enqueue, this->shared_from_this(), msg)); }

    void plain_websocket_session::close(boost::beast::websocket::close_reason const &cr) { websocket.async_close(cr, boost::beast::bind_front_handler(&plain_websocket_session::on_close, this->shared_from_this())); }

    void plain_websocket_session::on_accept(boost::beast::error_code ec)
    {
        if (ec)
            throw std::runtime_error(ec.message());

        fire_on_open();

        do_read();
    }

    void plain_websocket_session::do_read() { websocket.async_read(buffer, boost::beast::bind_front_handler(&plain_websocket_session::on_read, this->shared_from_this())); }

    void plain_websocket_session::on_read(boost::beast::error_code ec, std::size_t)
    {
        if (ec == boost::beast::websocket::error::closed) // This indicates that the session was closed
            return fire_on_close(websocket.reason());
        else if (ec)
            throw std::runtime_error(ec.message());

        fire_on_message(std::make_shared<const std::string>(boost::beast::buffers_to_string(buffer.data())));

        buffer.consume(buffer.size());

        do_read();
    }

    void plain_websocket_session::enqueue(const std::shared_ptr<const std::string> &msg)
    {
        send_queue.push(msg);

        if (send_queue.size() > 1)
            return; // already sending

        do_write();
    }

    void plain_websocket_session::do_write() { websocket.async_write(boost::asio::buffer(*send_queue.front()), boost::asio::bind_executor(websocket.get_executor(), boost::beast::bind_front_handler(&plain_websocket_session::on_write, this->shared_from_this()))); }

    void plain_websocket_session::on_write(boost::beast::error_code ec, std::size_t)
    {
        if (ec)
            throw std::runtime_error(ec.message());

        send_queue.pop();

        if (!send_queue.empty())
            do_write();
    }

    void plain_websocket_session::on_close(boost::beast::error_code ec)
    {
        if (ec)
            throw std::runtime_error(ec.message());

        fire_on_close(websocket.reason());
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

    void ssl_session::do_read()
    {
        parser.emplace();                                                               // Construct a new parser for each message
        parser->body_limit(10000);                                                      // Set the limit on the allowed size of a message
        boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30)); // Set the timeout

        boost::beast::http::async_read(stream, buffer, *parser, boost::beast::bind_front_handler(&ssl_session::on_read, this->shared_from_this())); // Read a request
    }

    void ssl_session::on_read(boost::beast::error_code ec, std::size_t)
    {
        if (ec == boost::beast::http::error::end_of_stream)
            return do_eof();
        else if (ec)
            throw std::runtime_error(ec.message());

        if (boost::beast::websocket::is_upgrade(parser->get()))
        {
            boost::beast::get_lowest_layer(stream).expires_never();
            auto req = parser->release();
            auto handler = get_wss_handler(req.target().to_string());
            if (handler)
                std::make_shared<ssl_websocket_session>(srv, std::move(stream), handler.value())->do_accept(std::move(req));
        }

        handle_request(parser->release()); // Handle the HTTP request
    }

    void ssl_session::on_write(bool keep_alive, boost::beast::error_code ec, std::size_t)
    {
        if (ec)
            throw std::runtime_error(ec.message());

        if (!keep_alive) // This means we should close the connection, usually because the response indicated the "Connection: close" semantic.
            return do_eof();

        response_queue.pop();

        do_read();
    }

    void ssl_session::on_shutdown(boost::beast::error_code ec)
    {
        if (ec)
            throw std::runtime_error(ec.message());
    }

    void ssl_websocket_session::send(const std::shared_ptr<const std::string> &msg) { boost::asio::post(websocket.get_executor(), boost::beast::bind_front_handler(&ssl_websocket_session::enqueue, this->shared_from_this(), msg)); }

    void ssl_websocket_session::close(boost::beast::websocket::close_reason const &cr) { websocket.async_close(cr, boost::beast::bind_front_handler(&ssl_websocket_session::on_close, this->shared_from_this())); }

    void ssl_websocket_session::on_accept(boost::beast::error_code ec)
    {
        if (ec)
            return fire_on_error(ec);

        fire_on_open();

        do_read();
    }

    void ssl_websocket_session::do_read() { websocket.async_read(buffer, boost::beast::bind_front_handler(&ssl_websocket_session::on_read, this->shared_from_this())); }

    void ssl_websocket_session::on_read(boost::beast::error_code ec, std::size_t)
    {
        if (ec == boost::beast::websocket::error::closed) // This indicates that the session was closed
            return fire_on_close(websocket.reason());
        else if (ec)
            throw std::runtime_error(ec.message());

        fire_on_message(std::make_shared<const std::string>(boost::beast::buffers_to_string(buffer.data())));

        buffer.consume(buffer.size());

        do_read();
    }

    void ssl_websocket_session::enqueue(const std::shared_ptr<const std::string> &msg)
    {
        send_queue.push(msg);

        if (send_queue.size() > 1)
            return; // already sending

        do_write();
    }

    void ssl_websocket_session::do_write() { websocket.async_write(boost::asio::buffer(*send_queue.front()), boost::asio::bind_executor(websocket.get_executor(), boost::beast::bind_front_handler(&ssl_websocket_session::on_write, this->shared_from_this()))); }

    void ssl_websocket_session::on_write(boost::beast::error_code ec, std::size_t)
    {
        if (ec)
            throw std::runtime_error(ec.message());

        send_queue.pop();

        if (!send_queue.empty())
            do_write();
    }

    void ssl_websocket_session::on_close(boost::beast::error_code ec)
    {
        if (ec)
            throw std::runtime_error(ec.message());

        fire_on_close(websocket.reason());
    }
#endif
} // namespace network::async