#include "ws_client.hpp"
#include "sha1.hpp"
#include "base64.hpp"
#include "request.hpp"
#include "response.hpp"
#include "logging.hpp"

namespace network
{
#ifdef ENABLE_SSL
    ws_client::ws_client(const std::string &host, unsigned short port, std::function<void()> on_open_handler, std::function<void(std::string_view)> on_message_handler, std::function<void()> on_close_handler, std::function<void(const std::error_code &)> on_error_handler) : host(host), port(port), resolver(io_ctx), socket(io_ctx, ssl_ctx), on_open_handler(on_open_handler), on_message_handler(on_message_handler), on_close_handler(on_close_handler), on_error_handler(on_error_handler) { connect(); }
#else
    ws_client::ws_client(const std::string &host, unsigned short port, std::function<void()> on_open_handler, std::function<void(std::string_view)> on_message_handler, std::function<void()> on_close_handler, std::function<void(const std::error_code &)> on_error_handler) : host(host), port(port), resolver(io_ctx), socket(io_ctx), on_open_handler(on_open_handler), on_message_handler(on_message_handler), on_close_handler(on_close_handler), on_error_handler(on_error_handler) { connect(); }
#endif
    ws_client::~ws_client() { LOG_TRACE("WebSocket client destroyed"); }

    void ws_client::disconnect()
    {
        LOG_DEBUG("Disconnecting from " << host << ":" << port << "...");
        std::error_code ec;
#ifdef ENABLE_SSL
        socket.lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
#else
        socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
#endif
        if (ec == asio::error::eof)
        { // connection closed by server
            ec.clear();
            LOG_DEBUG("Connection closed by server");
        }
        else if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
#ifdef ENABLE_SSL
        socket.lowest_layer().close(ec);
#else
        socket.close(ec);
#endif
        if (ec)
            LOG_ERR(ec.message());
        LOG_DEBUG("Disconnected from " << host << ":" << port);
    }

    void ws_client::connect()
    {
        LOG_DEBUG("Connecting to " << host << ":" << port << "...");
        std::error_code ec;
#ifdef ENABLE_SSL
        asio::connect(socket.lowest_layer(), resolver.resolve(host, std::to_string(port)), ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
        socket.set_verify_mode(asio::ssl::verify_peer);
        socket.set_verify_callback(asio::ssl::host_name_verification(host));
        socket.handshake(asio::ssl::stream_base::client, ec);
#else
        asio::connect(socket, resolver.resolve(host, std::to_string(port)), ec);
#endif
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
        LOG_DEBUG("Connected to " << host << ":" << port);

        // send the WebSocket handshake request
        utils::sha1 sha1("dGhlIHNhbXBsZSBub25jZQ=="); // "dGhlIHNhbXBsZSBub25jZQ==" is the base64-encoded string "The WebSocket protocol"
        uint8_t digest[20];
        sha1.get_digest_bytes(digest);
        std::string key = utils::base64_encode(digest, 20);

        std::map<std::string, std::string> hdrs;
        hdrs["Host"] = host + ":" + std::to_string(port);
        hdrs["Upgrade"] = "websocket";
        hdrs["Connection"] = "Upgrade";
        hdrs["Sec-WebSocket-Key"] = key;
        hdrs["Sec-WebSocket-Version"] = "13";
        auto req = utils::make_u_ptr<request>(verb::Get, "/ws", "HTTP/1.1", std::move(hdrs));
        asio::write(socket, req->get_buffer(), ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        auto res = utils::make_u_ptr<response>();
        asio::read_until(socket, res->get_buffer(), "\r\n\r\n", ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        if (res->get_status_code() != status_code::websocket_switching_protocols)
        {
            LOG_ERR("WebSocket handshake failed");
            return;
        }
    }
} // namespace network
