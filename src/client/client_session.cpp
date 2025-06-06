#include "client_session.hpp"
#include "async_client.hpp"
#include "logging.hpp"

namespace network
{
    client_session_base::client_session_base(async_client_base &client, std::string_view host, unsigned short port) : client(client), host(host), port(port), strand(asio::make_strand(client.io_ctx)) {}
    client_session_base::~client_session_base() {}

    void client_session_base::run()
    {
    }

    void client_session_base::enqueue(std::unique_ptr<request> req, std::function<void(const response &)> &&cb)
    {
        asio::post(strand, [self = shared_from_this(), req = std::move(req), cb = std::move(cb)]() mutable
                   { self->request_queue.emplace(std::move(req), std::move(cb)); });
    }
    void client_session_base::enqueue(std::unique_ptr<response> res, std::function<void(const response &)> &&cb)
    {
        asio::post(strand, [self = shared_from_this(), res = std::move(res), cb = std::move(cb)]() mutable
                   { self->response_queue.emplace(std::move(res), std::move(cb)); });
    }

    client_session::client_session(async_client_base &client, std::string_view host, unsigned short port, asio::ip::tcp::socket &&socket) : client_session_base(client, host, port), socket(std::move(socket)) {}

    void client_session::connect(asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, std::function<void(const asio::error_code &, const asio::ip::tcp::endpoint &)> callback) { asio::async_connect(socket, endpoints, callback); }
    void client_session::read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read(socket, buffer, asio::transfer_exactly(size), callback); }
    void client_session::read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read_until(socket, buffer, delimiter, callback); }
    void client_session::write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_write(socket, buffer, callback); }

#ifdef ENABLE_SSL
    ssl_client_session::ssl_client_session(async_client_base &client, std::string_view host, unsigned short port, asio::ssl::stream<asio::ip::tcp::socket> &&socket) : client_session_base(client, host, port), socket(std::move(socket))
    {
        if (!SSL_set_tlsext_host_name(socket.native_handle(), host.data()))
        {
            LOG_ERR("SSL_set_tlsext_host_name failed");
            throw std::runtime_error("SSL_set_tlsext_host_name failed");
        }
    }

    void ssl_client_session::connect(asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, std::function<void(const asio::error_code &, const asio::ip::tcp::endpoint &)> callback)
    {
        asio::async_connect(socket.next_layer(), endpoints, [this, self = shared_from_this(), callback](const asio::error_code &ec, const asio::ip::tcp::endpoint &endpoint) mutable
                            {
                                if (ec)
                                    return callback(ec, endpoint);
                                socket.async_handshake(asio::ssl::stream_base::client, [self = shared_from_this(), callback, &endpoint](const asio::error_code &ec)
                                    { callback(ec, endpoint); }); });
    }
    void ssl_client_session::read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read(socket, buffer, asio::transfer_exactly(size), callback); }
    void ssl_client_session::read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read_until(socket, buffer, delimiter, callback); }
    void ssl_client_session::write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_write(socket, buffer, callback); }
#endif
} // namespace network
