#include "http_session.h"
#include "logging.h"
#include "websocket_session.h"

namespace network
{
    http_session::http_session(boost::asio::ip::tcp::socket &&socket) : socket(std::move(socket)) {}

    void http_session::run()
    {
        LOG("Running HTTP session..");
        boost::beast::http::async_read(socket, buffer, request, [this](boost::system::error_code ec, std::size_t bytes_transferred)
                                       { on_read(ec, bytes_transferred); });
    }

    void http_session::on_read(boost::system::error_code ec, std::size_t)
    {
        LOG("Received: " << boost::beast::buffers_to_string(buffer.data()));
        if (ec == boost::beast::http::error::end_of_stream)
        {
            socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
            return;
        }
        else if (ec)
        {
            LOG_ERR("Error on read: " << ec.message());
            delete this;
            return;
        }

        if (boost::beast::websocket::is_upgrade(request))
        {
            (new websocket_session(std::move(socket)))->run(std::move(request));
            delete this;
            return;
        }

        boost::beast::http::response<boost::beast::http::string_body> response;
        response.version(request.version());
        response.keep_alive(false);
        response.set(boost::beast::http::field::server, "Beast");
        response.set(boost::beast::http::field::content_type, "text/plain");
        response.body() = "Hello, world!";
        response.prepare_payload();
        LOG("Sending: " << response);
        boost::beast::http::async_write(socket, response, [this, &response](boost::system::error_code ec, std::size_t bytes_transferred)
                                        { on_write(ec, bytes_transferred, response.need_eof()); });
    }

    void http_session::on_write(boost::system::error_code ec, std::size_t, bool close)
    {
        LOG("Data sent..");
        if (ec)
        {
            LOG_ERR("Error on write: " << ec.message());
            delete this;
            return;
        }

        if (close)
        {
            socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
            return;
        }

        request = {};
        buffer.consume(buffer.size());

        boost::beast::http::async_read(socket, buffer, request, [this](boost::system::error_code ec, std::size_t bytes_transferred)
                                       { on_read(ec, bytes_transferred); });
    }

} // namespace network
