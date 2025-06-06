#include "server_session.hpp"
#include "server.hpp"
#include "logging.hpp"

namespace network
{
    server_session_base::server_session_base(server_base &server) : server(server), strand(asio::make_strand(server.io_ctx)) {}
    server_session_base::~server_session_base() {}

    void server_session_base::run()
    {
    }

    void server_session_base::enqueue(std::unique_ptr<request> req)
    {
        asio::post(strand, [self = shared_from_this(), req = std::move(req)]() mutable
                   { self->request_queue.emplace(std::move(req)); });
    }

    void server_session_base::enqueue(std::unique_ptr<response> res)
    {
        asio::post(strand, [self = shared_from_this(), res = std::move(res)]() mutable
                   { self->response_queue.emplace(std::move(res)); });
    }

    server_session::server_session(server_base &server, asio::ip::tcp::socket &&socket) : server_session_base(server), socket(std::move(socket)) {}

    void server_session::read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read(socket, buffer, asio::transfer_exactly(size), callback); }
    void server_session::read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read_until(socket, buffer, delimiter, callback); }
    void server_session::write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_write(socket, buffer, callback); }

#ifdef ENABLE_SSL
    ssl_server_session::ssl_server_session(server_base &server, asio::ssl::stream<asio::ip::tcp::socket> &&socket) : server_session_base(server), socket(std::move(socket)) {}

    void ssl_server_session::read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read(socket, buffer, asio::transfer_exactly(size), callback); }
    void ssl_server_session::read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read_until(socket, buffer, delimiter, callback); }
    void ssl_server_session::write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_write(socket, buffer, callback); }
#endif
} // namespace network
