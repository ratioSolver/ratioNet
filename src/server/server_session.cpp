#include "server_session.hpp"
#include "server.hpp"
#include "sha1.hpp"
#include "base64.hpp"
#include "ws_server_session.hpp"
#include "logging.hpp"

namespace network
{
    server_session_base::server_session_base(server_base &server) : server(server), strand(asio::make_strand(server.io_ctx)) {}
    server_session_base::~server_session_base() {}

    void server_session_base::run() { read_until(buffer, "\r\n\r\n", std::bind(&server_session_base::on_read_headers, shared_from_this(), std::placeholders::_1, std::placeholders::_2)); }

    void server_session_base::upgrade()
    {
        auto key_it = current_request->headers.find("sec-websocket-key");
        if (key_it == current_request->headers.end())
        {
            LOG_ERR("WebSocket key not found");
            return;
        }

        // the handshake response, the key is concatenated with the GUID and hashed with SHA-1 and then base64 encoded
        utils::sha1 sha1(key_it->second + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        uint8_t digest[20];
        sha1.get_digest_bytes(digest);
        std::string key = utils::base64_encode(digest, 20);

        // create the upgrade response
        response_queue.emplace(std::make_unique<response>(status_code::websocket_switching_protocols, std::multimap<std::string, std::string>{{"Upgrade", "websocket"}, {"Connection", "Upgrade"}, {"Sec-WebSocket-Accept", key}}));
        write(get_next_response().get_buffer(), std::bind(&server_session_base::on_upgrade, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
    }

    void server_session_base::enqueue(std::unique_ptr<response> res)
    {
        asio::post(strand, [this, self = shared_from_this(), res = std::move(res)]() mutable
                   { response_queue.emplace(std::move(res));
                     if (response_queue.size() == 1) // If this is the first response, start writing
                         write(get_next_response().get_buffer(), std::bind(&server_session_base::on_write, self, std::placeholders::_1, std::placeholders::_2)); });
    }

    void server_session_base::on_write(const asio::error_code &ec, std::size_t)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        response_queue.pop(); // Remove the response that has been sent

        if (!response_queue.empty()) // If there are more responses to send, write the next one
            write(get_next_response().get_buffer(), std::bind(&server_session_base::on_write, shared_from_this(), asio::placeholders::error, asio::placeholders::bytes_transferred));
    }
    void server_session_base::on_read_headers(const asio::error_code &ec, std::size_t bytes_transferred)
    {
        if (ec == asio::error::eof)
            return; // connection closed by client
#ifdef ENABLE_SSL
        else if (ec == asio::ssl::error::stream_truncated)
            return; // connection closed by client
#endif
        else if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        // the buffer may contain additional bytes beyond the delimiter
        std::size_t additional_bytes = buffer.size() - bytes_transferred;

        current_request = std::make_unique<request>(buffer); // Create a new request object from the buffer

        if (current_request->is_upgrade()) // handle websocket upgrade request
            return upgrade();

        if (auto cl_range = current_request->headers.equal_range("content-length"); cl_range.first != cl_range.second)
        { // read body
            std::size_t content_length = std::stoul(cl_range.first->second);
            if (content_length > additional_bytes) // read the remaining body
                read(buffer, content_length - additional_bytes, std::bind(&server_session_base::on_read_body, shared_from_this(), asio::placeholders::error, asio::placeholders::bytes_transferred));
            else // the buffer contains the entire body
                on_read_body(ec, bytes_transferred);
        }
        else if (auto te_range = current_request->headers.equal_range("transfer-encoding"); te_range.first != te_range.second && te_range.first->second == "chunked")
            read_chunk();
        else
        { // Handle the request with the server
            server.handle_request(*this, *current_request);

            if (current_request->is_keep_alive())
                read_until(buffer, "\r\n\r\n", std::bind(&server_session_base::on_read_headers, shared_from_this(), asio::placeholders::error, asio::placeholders::bytes_transferred));
        }
    }
    void server_session_base::on_read_body(const asio::error_code &ec, std::size_t)
    {
        if (ec == asio::error::eof)
            return; // connection closed by client
        else if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        if (current_request->accumulated_body.empty())
        {
            std::size_t content_length = std::stoul(current_request->headers.equal_range("content-length").first->second);
            std::string body;
            body.reserve(content_length);
            body.assign(asio::buffers_begin(buffer.data()), asio::buffers_begin(buffer.data()) + content_length);
            buffer.consume(content_length); // Consume the body from the buffer
            if (current_request->headers.equal_range("content-type").first->second == "application/json")
                current_request = std::make_unique<json_request>(current_request->v, std::move(current_request->target), std::move(current_request->version), std::move(current_request->headers), json::load(body));
            else
                current_request = std::make_unique<string_request>(current_request->v, std::move(current_request->target), std::move(current_request->version), std::move(current_request->headers), std::move(body));
        }
        else
        {
            if (current_request->headers.equal_range("content-type").first->second == "application/json")
                current_request = std::make_unique<json_request>(current_request->v, std::move(current_request->target), std::move(current_request->version), std::move(current_request->headers), json::load(current_request->accumulated_body));
            else
                current_request = std::make_unique<string_request>(current_request->v, std::move(current_request->target), std::move(current_request->version), std::move(current_request->headers), std::move(current_request->accumulated_body));
        }

        server.handle_request(*this, *current_request); // Handle the request with the server

        if (current_request->is_keep_alive())
            read_until(buffer, "\r\n\r\n", std::bind(&server_session_base::on_read_headers, shared_from_this(), asio::placeholders::error, asio::placeholders::bytes_transferred));
    }
    void server_session_base::read_chunk()
    {
        read_until(buffer, "\r\n", [this, self = shared_from_this()](const std::error_code &ec, std::size_t bytes_transferred)
                   {
            if (ec)
            {
                LOG_ERR("Error reading chunk: " << ec.message());
                return;
            }

            // The buffer may contain additional bytes beyond the delimiter
            std::size_t additional_bytes = buffer.size() - bytes_transferred;

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
            if (size == 0)                                              // If chunk size is 0, read the trailing CRLF
                self->read_until(buffer, "\r\n", [this, self](const std::error_code &ec, std::size_t bytes_transferred)
                                 {
                                     if (ec)
                                     {
                                         LOG_ERR("Error reading trailing CRLF: " << ec.message());
                                         return;
                                     }
                                     buffer.consume(2); // Consume the trailing CRLF
                                     self->on_read_body(ec, bytes_transferred);             // Call on_read_body to process the response
                                 });
            else if (size > additional_bytes) // If chunk size is greater than additional bytes, read the remaining chunk
                self->read(buffer, size - additional_bytes, [this, self, size](const std::error_code &ec, std::size_t)
                           {
                               if (ec)
                               {
                                   LOG_ERR("Error reading chunk body: " << ec.message());
                                   return;
                               }
                               current_request->accumulated_body.reserve(current_request->accumulated_body.size() + size);
                               current_request->accumulated_body.append(asio::buffers_begin(buffer.data()), asio::buffers_begin(buffer.data()) + size);
                               buffer.consume(size + 2); // Consume the chunk body and the trailing CRLF
                               self->read_chunk(); // Read the next chunk
                           });
            else 
                { // The buffer contains the entire chunk, append it to the body and read the next chunk
                    current_request->accumulated_body.reserve(current_request->accumulated_body.size() + size);
                    current_request->accumulated_body.append(asio::buffers_begin(buffer.data()), asio::buffers_begin(buffer.data()) + size);
                    buffer.consume(size + 2); // Consume the chunk body and the trailing CRLF
                    self->read_chunk(); // Read the next chunk
                } });
    }

    server_session::server_session(server_base &server, asio::ip::tcp::socket &&socket) : server_session_base(server), socket(std::move(socket)) {}
    server_session::~server_session()
    {
        if (is_connected())
            disconnect(); // Ensure the socket is closed when the session is destroyed
    }

    bool server_session::is_connected() const { return socket.is_open(); }

    void server_session::disconnect()
    {
        asio::error_code ec;

        // Gracefully shutdown the socket
        socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        if (ec && ec != asio::error::eof && ec != asio::error::not_connected)
            LOG_ERR("Error shutting down socket: " << ec.message());

        // Close the socket
        socket.close(ec);
        if (ec)
            LOG_ERR("Error closing socket: " << ec.message());

        LOG_DEBUG("Disconnected from client");
    }

    void server_session::on_upgrade(const asio::error_code &ec, std::size_t)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
        // the upgrade response has been sent, now we can start a WebSocket session
        std::make_shared<ws_server_session>(get_server(), get_current_request().get_target(), std::move(socket))->run();
    }

    void server_session::read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read(socket, buffer, asio::transfer_exactly(size), callback); }
    void server_session::read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read_until(socket, buffer, delimiter, callback); }
    void server_session::write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_write(socket, buffer, callback); }

#ifdef ENABLE_SSL
    ssl_server_session::ssl_server_session(server_base &server, asio::ssl::stream<asio::ip::tcp::socket> &&socket) : server_session_base(server), socket(std::move(socket)) {}
    ssl_server_session::~ssl_server_session()
    {
        if (is_connected())
            disconnect(); // Ensure the socket is closed when the session is destroyed
    }

    void ssl_server_session::handshake(std::function<void(const std::error_code &)> callback) { socket.async_handshake(asio::ssl::stream_base::server, callback); }

    bool ssl_server_session::is_connected() const { return socket.next_layer().is_open(); }

    void ssl_server_session::disconnect()
    {
        asio::error_code ec;

        // Gracefully shutdown the SSL socket
        socket.shutdown(ec);
        if (ec && ec != asio::ssl::error::stream_truncated)
            LOG_ERR("Error shutting down SSL socket: " << ec.message());

        // Shutdown the underlying TCP socket
        socket.next_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        if (ec && ec != asio::error::eof && ec != asio::error::not_connected)
            LOG_ERR("Error shutting down TCP socket: " << ec.message());

        // Close the underlying TCP socket
        socket.next_layer().close(ec);
        if (ec)
            LOG_ERR("Error closing SSL socket: " << ec.message());

        LOG_DEBUG("Disconnected from client");
    }

    void ssl_server_session::on_upgrade(const asio::error_code &ec, std::size_t)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
        // the upgrade response has been sent, now we can start a WebSocket session
        std::make_shared<wss_server_session>(get_server(), get_current_request().get_target(), std::move(socket))->run();
    }

    void ssl_server_session::read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read(socket, buffer, asio::transfer_exactly(size), callback); }
    void ssl_server_session::read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read_until(socket, buffer, delimiter, callback); }
    void ssl_server_session::write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_write(socket, buffer, callback); }
#endif
} // namespace network
