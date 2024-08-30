#include "session.hpp"
#include "sha1.hpp"
#include "base64.hpp"
#include "ws_session.hpp"
#include "server.hpp"
#include "logging.hpp"

namespace network
{
#ifdef ENABLE_SSL
    session::session(server &srv, asio::ssl::stream<asio::ip::tcp::socket> &&socket) : srv(srv), endpoint(socket.lowest_layer().remote_endpoint()), socket(std::move(socket)), strand(asio::make_strand(srv.io_ctx)) { LOG_TRACE("Session created with " << this->socket.lowest_layer().remote_endpoint()); }
#else
    session::session(server &srv, asio::ip::tcp::socket &&socket) : srv(srv), endpoint(socket.remote_endpoint()), socket(std::move(socket)), strand(asio::make_strand(srv.io_ctx)) { LOG_TRACE("Session created with " << this->socket.remote_endpoint()); }
#endif
    session::~session() { LOG_TRACE("Session destroyed with " << endpoint); }

#ifdef ENABLE_SSL
    void session::handshake() { socket.async_handshake(asio::ssl::stream_base::server, std::bind(&session::on_handshake, shared_from_this(), asio::placeholders::error)); }

    void session::on_handshake(const std::error_code &ec)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        read();
    }
#endif

    void session::read()
    {
        req = std::make_unique<request>();
        asio::async_read_until(socket, req->buffer, "\r\n\r\n", std::bind(&session::on_read, shared_from_this(), asio::placeholders::error, asio::placeholders::bytes_transferred));
    }

    void session::enqueue(std::unique_ptr<response> res)
    {
        asio::post(strand, [self = shared_from_this(), r = std::move(res)]() mutable
                   { self->res_queue.push(std::move(r));
                            if (self->res_queue.size() == 1)
                                self->write(); });
    }
    void session::write() { asio::async_write(socket, res_queue.front()->get_buffer(), std::bind(&session::on_write, shared_from_this(), asio::placeholders::error, asio::placeholders::bytes_transferred)); }

    void session::upgrade()
    {
        auto key_it = req->headers.find("Sec-WebSocket-Key");
        if (key_it == req->headers.end())
        {
            LOG_ERR("WebSocket key not found");
            return;
        }

        // the handshake response, the key is concatenated with the GUID and hashed with SHA-1 and then base64 encoded
        utils::sha1 sha1(key_it->second + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        uint8_t digest[20];
        sha1.get_digest_bytes(digest);
        std::string key = utils::base64_encode(digest, 20);

        auto res = std::make_unique<response>(status_code::websocket_switching_protocols, std::map<std::string, std::string>{{"Upgrade", "websocket"}, {"Connection", "Upgrade"}, {"Sec-WebSocket-Accept", key}});
        auto &buf = res->get_buffer();
        asio::async_write(socket, buf, [self = shared_from_this(), res = std::move(res)](const std::error_code &ec, std::size_t bytes_transferred)
                          { if (ec) { LOG_ERR(ec.message()); return; } std::make_shared<ws_session>(self->srv, self->req->target, std::move(self->socket))->start(); });
    }

    void session::on_read(const std::error_code &ec, std::size_t bytes_transferred)
    {
        if (ec == asio::error::eof)
            return; // connection closed by client
        else if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        // the buffer may contain additional bytes beyond the delimiter
        std::size_t additional_bytes = req->buffer.size() - bytes_transferred;

        req->parse(); // parse the request line and headers

        if (req->is_upgrade()) // handle websocket upgrade request
            return upgrade();

        if (req->headers.find("Content-Length") != req->headers.end())
        { // read body
            std::size_t content_length = std::stoul(req->headers["Content-Length"]);
            if (content_length > additional_bytes) // read the remaining body
                asio::async_read(socket, req->buffer, asio::transfer_exactly(content_length - additional_bytes), std::bind(&session::on_body, shared_from_this(), asio::placeholders::error, asio::placeholders::bytes_transferred));
            else // the buffer contains the entire body
                on_body(ec, bytes_transferred);
        }
        else // no body
            srv.handle_request(*this, std::move(req));
    }

    void session::on_body(const std::error_code &ec, std::size_t)
    {
        if (ec == asio::error::eof)
            return; // connection closed by client
        else if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        std::istream is(&req->buffer);
        if (req->headers.find("Content-Type") != req->headers.end() && req->headers["Content-Type"] == "application/json")
            req = std::make_unique<json_request>(req->v, std::move(req->target), std::move(req->version), std::move(req->headers), json::load(is));
        else
        {
            std::string body;
            while (is.peek() != EOF)
                body += is.get();
            req = std::make_unique<string_request>(req->v, std::move(req->target), std::move(req->version), std::move(req->headers), std::move(body));
        }
        srv.handle_request(*this, std::move(req));
    }

    void session::on_write(const std::error_code &ec, std::size_t)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        res_queue.pop();
        if (!res_queue.empty())
            write(); // write the next message
    }
} // namespace network
