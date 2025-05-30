#include "server_session.hpp"
#include "server.hpp"
#include "logging.hpp"

namespace network
{
    server_session_base::server_session_base(server_base &server) : server(server), strand(asio::make_strand(server.io_ctx)) {}
    server_session_base::~server_session_base() {}

    request &server_session_base::create_request()
    {
        request_queue.push(std::make_unique<request>());
        return *request_queue.back();
    }

    void server_session_base::enqueue(std::unique_ptr<response> res)
    {
        asio::post(strand, [self = shared_from_this(), res = std::move(res)]() mutable
                   { self->response_queue.emplace(std::move(res)); });
    }

    void server_session_base::on_read(request &req, const std::error_code &ec, std::size_t bytes_transferred)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        // the buffer may contain additional bytes beyond the delimiter
        std::size_t additional_bytes = req.buffer.size() - bytes_transferred;

        req.parse(); // parse the request line and headers
    }

    server_session::server_session(server_base &server, asio::ip::tcp::socket &&socket) : server_session_base(server), socket(std::move(socket)) {}

    void server_session::read()
    {
        request &req = create_request();
        asio::async_read_until(socket, req.get_buffer(), "\r\n\r\n", [self = shared_from_this(), &req](const std::error_code &ec, std::size_t bytes_transferred)
                               { if (ec != asio::error::eof) self->on_read(req, ec, bytes_transferred); });
    }
} // namespace network
