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

        if (boost::beast::websocket::is_upgrade(parser->get()))
        {                                                           // If this is a WebSocket upgrade request, transfer control to a WebSocket session
            boost::beast::get_lowest_layer(stream).expires_never(); // Turn off the timeout on the tcp_stream, because the websocket stream has its own timeout system.
            new ssl_websocket_session(srv, std::move(stream), parser->release());
            delete this; // Delete this session
            return;
        }

        work_queue.emplace(new request_handler_impl(*this, parser->release())); // Send the request to the queue
        if (work_queue.size() == 1)                                             // If this is the first request in the queue, we need to start the work
            work_queue.back()->handle_request();
        if (work_queue.size() < queue_limit) // If we aren't at the queue limit, try to pipeline another request
            do_read();
    }

    void ssl_http_session::on_write(boost::beast::error_code ec, std::size_t, bool close)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        if (close) // This means we should close the connection, usually because the response indicated the "Connection: close" semantic.
            return do_eof();

        work_queue.pop();                    // Remove the current request from the queue
        if (work_queue.size() < queue_limit) // If we aren't at the queue limit, try to pipeline another request
            do_read();
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

    void ssl_websocket_session::send(const std::string &msg)
    {
        // post to strand to avoid concurrent write..
        boost::asio::post(ws.get_executor(), [this, msg]()
                          { ws.async_write(boost::asio::buffer(msg), [this](boost::beast::error_code ec, std::size_t bytes_transferred)
                                           { on_write(ec, bytes_transferred); }); });
    }

    void ssl_websocket_session::close(boost::beast::websocket::close_code code)
    {
        ws.async_close(code, [this](boost::beast::error_code ec)
                       { on_close(ec); });
    }

    boost::optional<ssl_ws_handler &> ssl_websocket_session::get_ssl_ws_handler(const std::string &path)
    {
        for (auto &handler : srv.ssl_ws_routes)
            if (std::regex_match(path, handler.first))
                return handler.second;
        return boost::none;
    }

    void ssl_websocket_session::on_accept(boost::beast::error_code ec)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            delete this;
        }

        do_read();
    }

    ssl_websocket_session::~ssl_websocket_session() { LOG_DEBUG("WebSocket session closed"); }

    void ssl_websocket_session::do_read()
    {
        ws.async_read(buffer, [this](boost::beast::error_code ec, std::size_t bytes_transferred)
                      { on_read(ec, bytes_transferred); });
    }

    void ssl_websocket_session::on_read(boost::beast::error_code ec, std::size_t)
    {
        if (ec == boost::beast::websocket::error::closed)
        { // This indicates that the session was closed
            delete this;
            return;
        }
        else if (ec)
        {
            LOG_ERR(ec.message());
            delete this;
            return;
        }
    }

    void ssl_websocket_session::on_write(boost::beast::error_code ec, std::size_t)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            delete this;
            return;
        }

        buffer.consume(buffer.size());

        do_read();
    }

    void ssl_websocket_session::on_close(boost::beast::error_code ec)
    {
        if (ec)
            LOG_ERR(ec.message());
        delete this;
    }
} // namespace network