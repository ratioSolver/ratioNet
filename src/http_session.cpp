#include "http_session.h"
#include "logging.h"
#include "websocket_session.h"

namespace network
{
    http_session::http_session(server &srv, boost::asio::ip::tcp::socket &&socket) : srv(srv), socket(std::move(socket)) { LOG("Created HTTP session with socket " << this->socket.native_handle()); }
    http_session::~http_session() { LOG("Destroyed HTTP session with socket " << socket.native_handle()); }

    void http_session::run()
    {
        LOG("Running HTTP session..");
        boost::beast::http::async_read(socket, buffer, request, [this](boost::system::error_code ec, std::size_t bytes_transferred)
                                       { on_read(ec, bytes_transferred); });
    }

    void http_session::on_read(boost::system::error_code ec, std::size_t)
    {
        LOG("Received: " << request);
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
            (new websocket_session(srv, std::move(socket)))->run(std::move(request));
            delete this;
            return;
        }

        auto res = new boost::beast::http::response<boost::beast::http::string_body>();
        res->version(request.version());
        res->keep_alive(false);
        res->set(boost::beast::http::field::server, "Beast");
        res->set(boost::beast::http::field::content_type, "text/plain");
        res->body() = "Hello world!";
        res->prepare_payload();

        LOG("Sending: " << *res);
        boost::beast::http::async_write(socket, *res, [this, res](boost::system::error_code ec, std::size_t bytes_transferred)
                                        { on_write(ec, bytes_transferred, res->need_eof()); delete res; });
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
            delete this;
            return;
        }

        request = {};
        buffer.consume(buffer.size());

        boost::beast::http::async_read(socket, buffer, request, [this](boost::system::error_code ec, std::size_t bytes_transferred)
                                       { on_read(ec, bytes_transferred); });
    }
} // namespace network
