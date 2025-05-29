#include "c.hpp"
#include "logging.hpp"

namespace network
{
    sync_client::sync_client(std::string_view host, unsigned short port) : io_ctx(), resolver(io_ctx), endpoints(resolver.resolve(host, std::to_string(port))) {}

    utils::u_ptr<response> sync_client::send(utils::u_ptr<request> req)
    {
        std::error_code ec;
        if (!is_connected())
            connect(endpoints, ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return nullptr;
        }

        write(req->get_buffer(), ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return nullptr;
        }
        auto res = utils::make_u_ptr<response>();

        std::size_t bytes_transferred = 0;
        while (true)
        {
            bytes_transferred = read_until(res->buffer, "\r\n\r\n", ec);
            if (ec == asio::error::eof)
            { // connection closed by server
                LOG_DEBUG("Connection closed by server");
                connect(endpoints, ec);
                ec.clear();
                write(req->get_buffer(), ec);
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
                read(res->buffer, len - additional_bytes, ec);
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
                bytes_transferred = read_until(res->buffer, "\r\n", ec); // read the chunk size
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
                    read_until(res->buffer, "\r\n", ec);
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
                    read(res->buffer, (size - additional_bytes) + 2, ec);
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
            disconnect(ec); // close the connection
        return res;
    }

    client::client(std::string_view host, unsigned short port) : sync_client(host, port), socket(io_ctx) {}
    bool client::is_connected() const { return socket.is_open(); }
    asio::ip::tcp::endpoint client::connect(const asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, asio::error_code &ec)
    {
        for (const auto &endpoint : endpoints)
            LOG_DEBUG("Trying to connect to " << endpoint.endpoint());
        auto endpoint = asio::connect(socket, endpoints, ec);
        if (ec)
            return endpoint;
        LOG_DEBUG("Connected to " << endpoint);
        return endpoint;
    }
    void client::disconnect(asio::error_code &ec)
    {
        if (!is_connected())
            return;
        socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        if (ec && ec != asio::error::not_connected)
            return;
        socket.close(ec);
    }
    std::size_t client::read(asio::streambuf &buffer, std::size_t size, asio::error_code &ec) { return asio::read(socket, buffer, asio::transfer_exactly(size), ec); }
    std::size_t client::read_until(asio::streambuf &buffer, std::string_view delim, asio::error_code &ec) { return asio::read_until(socket, buffer, delim, ec); }
    std::size_t client::write(asio::streambuf &buffer, asio::error_code &ec) { return asio::write(socket, buffer, ec); }

#ifdef ENABLE_SSL
    ssl_client::ssl_client(std::string_view host, unsigned short port) : sync_client(host, port), host(host), ssl_ctx(asio::ssl::context::sslv23), socket(io_ctx, ssl_ctx)
    {
        ssl_ctx.set_default_verify_paths();
        if (!SSL_set_tlsext_host_name(socket.native_handle(), host.data()))
        {
            LOG_ERR("SSL_set_tlsext_host_name failed");
            throw std::runtime_error("SSL_set_tlsext_host_name failed");
        }
    }

    asio::ip::tcp::endpoint ssl_client::connect(const asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, asio::error_code &ec)
    {
        auto endpoint = asio::connect(socket.lowest_layer(), endpoints, ec);
        if (ec)
            return endpoint;
        LOG_DEBUG("Connected to " << endpoint);
        socket.set_verify_mode(asio::ssl::verify_peer);
        socket.set_verify_callback(asio::ssl::host_name_verification(host));
        socket.handshake(asio::ssl::stream_base::client, ec);
        if (ec)
            return endpoint;
        LOG_DEBUG("SSL handshake completed with " << host);
        return endpoint;
    }
    void ssl_client::disconnect(asio::error_code &ec)
    {
        if (!is_connected())
            return;
        socket.lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        if (ec && ec != asio::error::not_connected)
            return;
        socket.lowest_layer().close(ec);
    }
    std::size_t ssl_client::read(asio::streambuf &buffer, std::size_t size, asio::error_code &ec) { return asio::read(socket, buffer, asio::transfer_exactly(size), ec); }
    std::size_t ssl_client::read_until(asio::streambuf &buffer, std::string_view delim, asio::error_code &ec) { return asio::read_until(socket, buffer, delim, ec); }
    std::size_t ssl_client::write(asio::streambuf &buffer, asio::error_code &ec) { return asio::write(socket, buffer, ec); }
#endif
} // namespace network