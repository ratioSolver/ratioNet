#include "client.hpp"
#include "verb.hpp"
#include "logging.hpp"

namespace network
{
#ifdef ENABLE_SSL
    client::client(std::string_view host, unsigned short port) : host(host), port(port), resolver(io_ctx), socket(io_ctx, ssl_ctx)
    {
        ssl_ctx.set_default_verify_paths();
        if (!SSL_set_tlsext_host_name(socket.native_handle(), host.data()))
        {
            LOG_ERR("SSL_set_tlsext_host_name failed");
            throw std::runtime_error("SSL_set_tlsext_host_name failed");
        }
        connect();
    }
#else
    client::client(std::string_view host, unsigned short port) : host(host), port(port), resolver(io_ctx), socket(io_ctx) { connect(); }
#endif
    client::~client() { disconnect(); }

    utils::u_ptr<response> client::send(utils::u_ptr<request> req)
    {
#ifdef ENABLE_SSL
        if (!socket.lowest_layer().is_open())
#else
        if (!socket.is_open())
#endif
            connect();

        std::error_code ec;
        asio::write(socket, req->get_buffer(), ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return nullptr;
        }
        auto res = utils::make_u_ptr<response>();

        std::size_t bytes_transferred = 0;
        while (true)
        {
            bytes_transferred = asio::read_until(socket, res->buffer, "\r\n\r\n", ec);
            if (ec == asio::error::eof)
            { // connection closed by server
                LOG_DEBUG("Connection closed by server");
                connect();
                ec.clear();
                asio::write(socket, req->get_buffer(), ec);
                if (ec)
                {
                    LOG_ERR(ec.message());
                    return nullptr;
                }
                continue; // retry the request
            }
            else if (ec)
            {
                LOG_ERR(ec.message());
                return nullptr;
            }
            break;
        }

        // the buffer may contain additional bytes beyond the delimiter
        std::size_t additional_bytes = res->buffer.size() - bytes_transferred;

        res->parse();

        if (res->get_headers().find("content-length") != res->get_headers().end())
        {
            auto len = std::stoul(res->get_headers().at("content-length"));
            if (len > additional_bytes)
            { // read the remaining body
                asio::read(socket, res->buffer, asio::transfer_exactly(len - additional_bytes), ec);
                if (ec)
                {
                    LOG_ERR(ec.message());
                    return nullptr;
                }
            }
            std::istream is(&res->buffer);
            if (res->get_headers().find("content-type") != res->get_headers().end() && res->get_headers().at("content-type") == "application/json")
                res = utils::make_u_ptr<json_response>(json::load(is), res->get_status_code(), std::move(res->headers));
            else
            {
                std::string body;
                body.reserve(len);
                while (is.peek() != EOF)
                    body += is.get();
                res = utils::make_u_ptr<string_response>(std::move(body), res->get_status_code(), std::move(res->headers));
            }
        }
        else if (res->get_headers().find("transfer-encoding") != res->get_headers().end() && res->get_headers().at("transfer-encoding") == "chunked")
        {
            std::string body;
            while (true)
            {
                bytes_transferred = asio::read_until(socket, res->buffer, "\r\n", ec); // read the chunk size
                if (ec)
                {
                    LOG_ERR(ec.message());
                    return nullptr;
                }
                // the buffer may contain additional bytes beyond the delimiter
                additional_bytes = res->buffer.size() - bytes_transferred;

                std::string chunk_size;
                std::vector<std::string> extensions;
                std::istream is(&res->buffer);
                while (is.peek() != '\r' && is.peek() != ';')
                    chunk_size += is.get();
                if (is.peek() == ';')
                {
                    is.get(); // consume ';'
                    while (is.peek() != '\r')
                    {
                        std::string extension;
                        while (is.peek() != ';' && is.peek() != '\r')
                            extension += is.get();
                        extensions.push_back(std::move(extension));
                        if (is.peek() == ';')
                            is.get(); // consume ';'
                    }
                }
                is.get(); // consume '\r'
                is.get(); // consume '\n'

                std::size_t size = std::stoul(chunk_size, nullptr, 16);
                if (size == 0)
                {
                    // read the trailing CRLF
                    asio::read_until(socket, res->buffer, "\r\n", ec);
                    if (ec)
                    {
                        LOG_ERR(ec.message());
                        return nullptr;
                    }
                    res->buffer.consume(2); // consume '\r\n'
                    break;
                }
                else if (size > additional_bytes)
                { // read the remaining chunk
                    asio::read(socket, res->buffer, asio::transfer_exactly((size - additional_bytes) + 2), ec);
                    if (ec)
                    {
                        LOG_ERR(ec.message());
                        return nullptr;
                    }
                }
                body.reserve(body.size() + size);
                body.append(asio::buffers_begin(res->buffer.data()), asio::buffers_begin(res->buffer.data()) + size);
                res->buffer.consume(size + 2); // consume chunk and '\r\n'
            }
            if (res->get_headers().find("content-type") != res->get_headers().end() && res->get_headers().at("content-type") == "application/json")
                res = utils::make_u_ptr<json_response>(json::load(body), res->get_status_code(), std::move(res->headers));
            else
                res = utils::make_u_ptr<string_response>(std::move(body), res->get_status_code(), std::move(res->headers));
        }

        if (res->get_headers().find("connection") != res->get_headers().end() && res->get_headers().at("connection") == "close")
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
    }
} // namespace network