#include "client_session.hpp"
#include "async_client.hpp"
#include "logging.hpp"

namespace network
{
    client_session_base::client_session_base(async_client_base &client) : client(client), strand(asio::make_strand(client.io_ctx)) {}
    client_session_base::~client_session_base() {}

    std::pair<std::unique_ptr<request>, std::function<void(const response &)>> &client_session_base::get_request() { return request_queue.front(); }

    void client_session_base::enqueue(std::unique_ptr<request> req, std::function<void(const response &)> &&cb)
    {
        asio::post(strand, [self = shared_from_this(), req = std::move(req), cb = std::move(cb)]() mutable
                   { self->request_queue.emplace(std::move(req), std::move(cb)); });
    }

    void client_session_base::on_write(std::function<void(const response &)> &&cb, const std::error_code &ec, std::size_t bytes_transferred)
    {
    }

    client_session::client_session(async_client_base &client, asio::ip::tcp::socket &&socket) : client_session_base(client), socket(std::move(socket)) {}

    void client_session::write()
    {
        auto &req = get_request();
        asio::async_write(socket, req.first->get_buffer(), [self = shared_from_this(), cb = std::move(req.second)](const std::error_code &ec, std::size_t bytes_transferred) mutable
                          { self->on_write(std::move(cb), ec, bytes_transferred); });
    }
} // namespace network
