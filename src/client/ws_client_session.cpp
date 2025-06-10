#include "ws_client_session.hpp"
#include "async_client.hpp"
#include "base64.hpp"
#include "logging.hpp"

namespace network
{
    ws_client_session_base::ws_client_session_base(async_client_base &client, std::string_view host, unsigned short port, std::string_view target) : client(client), host(host), port(port), target(target), resolver(client.io_ctx), endpoints(resolver.resolve(host, std::to_string(port))) {}
    ws_client_session_base::~ws_client_session_base() {}

    void ws_client_session_base::connect() { connect(endpoints, std::bind(&ws_client_session_base::on_connect, shared_from_this(), std::placeholders::_1, std::placeholders::_2)); }

    void ws_client_session_base::on_connect(const asio::error_code &ec, const asio::ip::tcp::endpoint &endpoint)
    {
        if (ec)
        {
            LOG_ERR("Connection error: " << ec.message());
            return;
        }
        LOG_DEBUG("Connected to " << host << ":" << port);

        // send the WebSocket handshake request
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(0, 255);

        std::array<unsigned char, 16> random_bytes;
        for (auto &byte : random_bytes)
            byte = static_cast<unsigned char>(dist(gen));

        std::map<std::string, std::string> hdrs;
        hdrs["Host"] = host + ":" + std::to_string(port);
        hdrs["Upgrade"] = "websocket";
        hdrs["Connection"] = "Upgrade";
        hdrs["Sec-WebSocket-Key"] = utils::base64_encode(random_bytes.data(), random_bytes.size());
        hdrs["Sec-WebSocket-Version"] = "13";

        auto req = std::make_shared<request>(verb::Get, std::string(target), "HTTP/1.1", std::move(hdrs));
    }

    ws_client_session::ws_client_session(async_client_base &client, std::string_view host, unsigned short port, std::string_view target, asio::ip::tcp::socket &&socket) : ws_client_session_base(client, host, port, target), socket(std::move(socket)) {}

    ws_client_session::~ws_client_session()
    {
        if (socket.is_open())
        {
            asio::error_code ec;
            socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            if (ec)
                LOG_ERR("Error shutting down socket: " << ec.message());
            socket.close(ec);
            if (ec)
                LOG_ERR("Error closing socket: " << ec.message());
        }
    }

    void ws_client_session::connect(asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, std::function<void(const asio::error_code &, const asio::ip::tcp::endpoint &)> callback) { asio::async_connect(socket, endpoints, callback); }

    void ws_client_session::read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read(socket, buffer, asio::transfer_exactly(size), callback); }
    void ws_client_session::write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_write(socket, buffer, callback); }

#ifdef ENABLE_SSL
    wss_client_session::wss_client_session(async_client_base &client, std::string_view host, unsigned short port, std::string_view target, asio::ssl::stream<asio::ip::tcp::socket> &&socket) : ws_client_session_base(client, host, port, target), socket(std::move(socket))
    {
        if (!SSL_set_tlsext_host_name(socket.native_handle(), host.data()))
        {
            LOG_ERR("SSL_set_tlsext_host_name failed");
            throw std::runtime_error("SSL_set_tlsext_host_name failed");
        }
    }

    wss_client_session::~wss_client_session()
    {
        if (socket.next_layer().is_open())
        {
            asio::error_code ec;
            socket.next_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            if (ec && ec != asio::error::not_connected)
                LOG_ERR("Error shutting down socket: " << ec.message());
            socket.next_layer().close(ec);
            if (ec)
                LOG_ERR("Error closing socket: " << ec.message());
        }
    }

    void wss_client_session::connect(asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, std::function<void(const asio::error_code &, const asio::ip::tcp::endpoint &)> callback)
    {
        asio::async_connect(socket.next_layer(), endpoints, [this, self = shared_from_this(), callback](const asio::error_code &ec, const asio::ip::tcp::endpoint &endpoint) mutable
                            {
                                if (ec)
                                    return callback(ec, endpoint);
                                socket.set_verify_mode(asio::ssl::verify_peer);
                                socket.set_verify_callback(asio::ssl::host_name_verification(host));
                                socket.async_handshake(asio::ssl::stream_base::client, [self = shared_from_this(), callback, &endpoint](const asio::error_code &ec)
                                                       { callback(ec, endpoint); }); });
    }

    void wss_client_session::read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read(socket.next_layer(), buffer, asio::transfer_exactly(size), callback); }
    void wss_client_session::write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_write(socket.next_layer(), buffer, callback); }
#endif
} // namespace network
