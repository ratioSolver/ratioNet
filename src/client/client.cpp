#include "client.hpp"
#include "logging.hpp"

namespace network
{
    client_base::client_base(std::string_view host, unsigned short port) : host(host), port(port), io_ctx(), resolver(io_ctx), endpoints(resolver.resolve(host, std::to_string(port))) {}

    std::unique_ptr<response> client_base::send(std::unique_ptr<request> req)
    {
        req->add_header("Host", host + ":" + std::to_string(port));

        if (!is_connected())
            connect(endpoints);
#ifdef ENABLE_SSL
        if (ec == asio::ssl::error::stream_truncated)
        { // connection closed by server
            LOG_DEBUG("Connection closed by server");
            connect(endpoints);
        }
#endif
        if (ec)
        {
            LOG_ERR(ec.message());
            return nullptr;
        }

        write(req->get_buffer());
        if (ec)
        {
            LOG_ERR(ec.message());
            return nullptr;
        }
        asio::streambuf buffer;

        std::size_t bytes_transferred = 0;
        while (true)
        {
            bytes_transferred = read_until(buffer, "\r\n\r\n");
            if (ec == asio::error::eof)
            { // connection closed by server
                LOG_DEBUG("Connection closed by server");
                connect(endpoints);
                if (ec)
                {
                    LOG_ERR(ec.message());
                    return nullptr;
                }
                write(req->get_buffer());
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
        std::size_t additional_bytes = buffer.size() - bytes_transferred;

        auto res = std::make_unique<response>(buffer);

        if (auto cl_i = res->get_headers().find("content-length"); cl_i != res->get_headers().end())
        { // read body based on content-length
            auto len = std::stoul(cl_i->second);
            if (len > additional_bytes)
            { // read the remaining body
                read(buffer, len - additional_bytes);
                if (ec)
                {
                    LOG_ERR(ec.message());
                    return nullptr;
                }
            }

            std::istream is(&buffer);
            if (res->is_json())
                res = std::make_unique<json_response>(json::load(is), res->get_status_code(), std::move(res->headers));
            else
            {
                std::string body;
                body.reserve(len);
                while (is.peek() != EOF)
                    body += is.get();
                res = std::make_unique<string_response>(std::move(body), res->get_status_code(), std::move(res->headers));
            }
        }
        else if (res->is_chunked())
        {
            while (true)
            {
                bytes_transferred = read_until(buffer, "\r\n"); // read the chunk size
                if (ec)
                {
                    LOG_ERR(ec.message());
                    return nullptr;
                }
                // the buffer may contain additional bytes beyond the delimiter
                additional_bytes = buffer.size() - bytes_transferred;

                std::string chunk_size;
                std::vector<std::string> extensions;
                std::istream is(&buffer);
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
                    read_until(buffer, "\r\n");
                    if (ec)
                    {
                        LOG_ERR(ec.message());
                        return nullptr;
                    }
                    buffer.consume(2); // consume '\r\n'
                    break;
                }
                else if (size > additional_bytes)
                { // read the remaining chunk
                    read(buffer, (size - additional_bytes) + 2);
                    if (ec)
                    {
                        LOG_ERR(ec.message());
                        return nullptr;
                    }
                }
                res->accumulated_body.reserve(res->accumulated_body.size() + size);
                res->accumulated_body.append(asio::buffers_begin(buffer.data()), asio::buffers_begin(buffer.data()) + size);
                buffer.consume(size + 2); // consume chunk and '\r\n'
            }
            if (res->is_json())
                res = std::make_unique<json_response>(std::move(res->accumulated_body), res->get_status_code(), std::move(res->headers));
            else
                res = std::make_unique<string_response>(std::move(res->accumulated_body), res->get_status_code(), std::move(res->headers));
        }

        if (res->is_closed())
            disconnect(); // close the connection
        return res;
    }

    client::client(std::string_view host, unsigned short port) : client_base(host, port), socket(io_ctx) {}
    client::~client()
    {
        if (is_connected())
            disconnect();
        if (ec && ec != asio::error::not_connected)
            LOG_ERR("Failed to disconnect: " << ec.message());
    }

    bool client::is_connected() const { return socket.is_open(); }
    asio::ip::tcp::endpoint client::connect(const asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints)
    {
        for ([[maybe_unused]] const auto &endpoint : endpoints)
            LOG_DEBUG("Trying to connect to " << endpoint.endpoint());
        auto endpoint = asio::connect(socket, endpoints, ec);
        if (ec)
            return endpoint;
        LOG_DEBUG("Connected to " << endpoint);
        return endpoint;
    }
    void client::disconnect()
    {
        socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        if (ec && ec != asio::error::not_connected)
            return;
        socket.close(ec);
    }

    std::size_t client::read(asio::streambuf &buffer, std::size_t size) { return asio::read(socket, buffer, asio::transfer_exactly(size), ec); }
    std::size_t client::read_until(asio::streambuf &buffer, std::string_view delim) { return asio::read_until(socket, buffer, delim, ec); }
    std::size_t client::write(asio::streambuf &buffer) { return asio::write(socket, buffer, ec); }

#ifdef ENABLE_SSL
    ssl_client::ssl_client(std::string_view host, unsigned short port) : client_base(host, port), ssl_ctx(asio::ssl::context::TLS_VERSION) { ssl_ctx.set_default_verify_paths(); }
    ssl_client::~ssl_client()
    {
        if (is_connected())
            disconnect();
        if (ec && ec != asio::error::not_connected)
            LOG_ERR("Failed to disconnect: " << ec.message());
    }

    bool ssl_client::is_connected() const { return socket && socket->lowest_layer().is_open(); }
    asio::ip::tcp::endpoint ssl_client::connect(const asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints)
    {
        socket = std::make_unique<asio::ssl::stream<asio::ip::tcp::socket>>(io_ctx, ssl_ctx);
        if (!SSL_set_tlsext_host_name(socket->native_handle(), host.data()))
        {
            LOG_ERR("SSL_set_tlsext_host_name failed");
            throw std::runtime_error("SSL_set_tlsext_host_name failed");
        }
        auto endpoint = asio::connect(socket->lowest_layer(), endpoints, ec);
        if (ec)
            return endpoint;
        LOG_DEBUG("Connected to " << endpoint);
        socket->set_verify_mode(asio::ssl::verify_peer);
        socket->set_verify_callback(asio::ssl::host_name_verification(host));
        socket->handshake(asio::ssl::stream_base::client, ec);
        if (ec)
            return endpoint;
        LOG_DEBUG("SSL handshake completed with " << host);
        return endpoint;
    }
    void ssl_client::disconnect()
    {
        socket->lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        if (ec && ec != asio::error::not_connected)
            return;
        socket->lowest_layer().close(ec);
    }

    std::size_t ssl_client::read(asio::streambuf &buffer, std::size_t size) { return asio::read(*socket, buffer, asio::transfer_exactly(size), ec); }
    std::size_t ssl_client::read_until(asio::streambuf &buffer, std::string_view delim) { return asio::read_until(*socket, buffer, delim, ec); }
    std::size_t ssl_client::write(asio::streambuf &buffer) { return asio::write(*socket, buffer, ec); }
#endif
} // namespace network