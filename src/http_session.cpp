#include "http_session.h"
#include "websocket_session.h"
#include "server.h"
#include "logging.h"

namespace network
{
    http_session::http_session(server &srv, boost::asio::ip::tcp::socket &&socket) : srv(srv), socket(std::move(socket)) { LOG("Created HTTP session with socket " << this->socket.native_handle()); }
    http_session::~http_session() { LOG("Destroyed HTTP session with socket " << socket.native_handle()); }

    void http_session::run()
    {
        LOG("Running HTTP session..");
        boost::beast::http::async_read(socket, buffer, req, [this](boost::system::error_code ec, std::size_t bytes_transferred)
                                       { on_read(ec, bytes_transferred); });
    }

    void http_session::on_read(boost::system::error_code ec, std::size_t)
    {
        LOG("Received: " << req);
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

        bool found = false;
        if (boost::beast::websocket::is_upgrade(req))
        {
            LOG("Upgrading to WebSocket..");
            for (auto &handler : srv.ws_routes)
                if (std::regex_match(req.target().to_string(), handler.first))
                {
                    found = true;
                    (new websocket_session(srv, std::move(socket), handler.second))->run(std::move(req));
                    break;
                }
            if (!found)
                LOG_WARN("No WebSocket handler found for " << req.target().to_string());
            delete this;
            return;
        }

        auto res = new boost::beast::http::response<boost::beast::http::string_body>{boost::beast::http::status::ok, req.version()};
        switch (req.method())
        {
        case boost::beast::http::verb::get:
            for (auto &handler : srv.get_routes)
                if (std::regex_match(req.target().to_string(), handler.first))
                {
                    found = true;
                    handler.second(req, *res);
                    break;
                }
            break;
        case boost::beast::http::verb::post:
            for (auto &handler : srv.post_routes)
                if (std::regex_match(req.target().to_string(), handler.first))
                {
                    found = true;
                    handler.second(req, *res);
                    break;
                }
            break;
        case boost::beast::http::verb::put:
            for (auto &handler : srv.put_routes)
                if (std::regex_match(req.target().to_string(), handler.first))
                {
                    found = true;
                    handler.second(req, *res);
                    break;
                }
            break;
        case boost::beast::http::verb::delete_:
            for (auto &handler : srv.delete_routes)
                if (std::regex_match(req.target().to_string(), handler.first))
                {
                    found = true;
                    handler.second(req, *res);
                    break;
                }
            break;
        default:
            res->result(boost::beast::http::status::bad_request);
            res->set(boost::beast::http::field::content_type, "text/plain");
            res->body() = "Invalid request method";
            break;
        }
        if (!found)
        {
            res->result(boost::beast::http::status::not_found);
            res->set(boost::beast::http::field::content_type, "text/plain");
            res->body() = "The resource '" + req.target().to_string() + "' was not found.";
        }
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

        req = {};
        buffer.consume(buffer.size());

        boost::beast::http::async_read(socket, buffer, req, [this](boost::system::error_code ec, std::size_t bytes_transferred)
                                       { on_read(ec, bytes_transferred); });
    }
} // namespace network
