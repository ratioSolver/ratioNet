#include "client.hpp"
#include "verb.hpp"
#include "logging.hpp"

namespace network
{

#ifdef ENABLE_SSL
    client::client(const std::string &host, unsigned short port) : host(host), port(port), resolver(io_ctx), socket(io_ctx, ssl_ctx) { connect(); }
#else
    client::client(const std::string &host, unsigned short port) : host(host), port(port), resolver(io_ctx), socket(io_ctx) { connect(); }
#endif

    std::unique_ptr<response> client::send(std::unique_ptr<request> req)
    {
#ifdef ENABLE_SSL
        if (!socket.lowest_layer().is_open())
#else
        if (!socket.is_open())
#endif
            connect();
        LOG_DEBUG("Sending request to " << host << ":" << port << "...");
        LOG_DEBUG(*req);
        std::error_code ec;
        asio::write(socket, req->get_buffer(), ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return nullptr;
        }
        auto res = std::make_unique<response>();
        std::size_t bytes_transferred = asio::read_until(socket, res->buffer, "\r\n\r\n", ec);
        LOG_DEBUG("Bytes transferred: " << bytes_transferred);
        if (ec)
        {
            LOG_ERR(ec.message());
            return nullptr;
        }
        // the buffer may contain additional bytes beyond the delimiter
        std::size_t additional_bytes = res->buffer.size() - bytes_transferred;
        LOG_DEBUG("Additional bytes: " << additional_bytes);

        res->parse();

        if (res->get_headers().find("Content-Length") != res->get_headers().end())
        {
            auto len = std::stoul(res->get_headers().at("Content-Length"));
            if (len > additional_bytes)
            {
                asio::read(socket, res->buffer, asio::transfer_exactly(len - additional_bytes), ec);
                if (ec)
                {
                    LOG_ERR(ec.message());
                    return nullptr;
                }
            }
            std::istream is(&res->buffer);
            if (res->get_headers().find("Content-Type") != res->get_headers().end() && res->get_headers().at("Content-Type") == "application/json")
                res = std::make_unique<json_response>(json::load(is), res->get_status_code(), std::move(res->headers));
            else
            {
                std::string body;
                while (is.peek() != EOF)
                    body += is.get();
                res = std::make_unique<string_response>(std::move(body), res->get_status_code(), std::move(res->headers));
            }
        }
        if (res->get_headers().find("Connection") != res->get_headers().end() && res->get_headers().at("Connection") == "close")
            disconnect(); // close the connection
        return res;
    }

    void client::disconnect()
    {
        LOG_DEBUG("Disconnecting from " << host << ":" << port << "...");
        std::error_code ec;
#ifdef ENABLE_SSL
        socket.lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
#else
        socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
#endif
        if (ec)
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

    void client::connect()
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
        SSL_set_tlsext_host_name(socket.native_handle(), host.c_str());
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
    }
} // namespace network