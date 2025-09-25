#include "client_session.hpp"
#include "async_client.hpp"
#include "logging.hpp"

namespace network
{
    client_session_base::client_session_base(async_client_base &client, std::string_view host, unsigned short port) : client(client), host(host), port(port), resolver(client.io_ctx), endpoints(resolver.resolve(host, std::to_string(port))), strand(asio::make_strand(client.io_ctx)) { LOG_TRACE("Client session created for " << host << ":" << port); }
    client_session_base::~client_session_base() { LOG_TRACE("Client session destroyed for " << host << ":" << port); }

    void client_session_base::connect()
    {
        asio::post(strand, [this, self = shared_from_this()]()
                   {
                    if (!is_connecting()) // If not already connecting, initiate a connection
                        connect(endpoints, std::bind(&client_session_base::on_connect, self, std::placeholders::_1, std::placeholders::_2)); });
    }

    void client_session_base::send(std::unique_ptr<request> req, std::function<void(const response &)> &&cb)
    {
        req->add_header("Host", host + ":" + std::to_string(port));
        asio::post(strand, [this, self = shared_from_this(), req = std::move(req), cb = std::move(cb)]() mutable
                   {
                    request_queue.emplace(std::move(req), std::move(cb));
                    if (!is_connected())
                    {
                        if (!is_connecting()) // If not already connecting, initiate a connection
                            connect(endpoints, std::bind(&client_session_base::on_connect, self, std::placeholders::_1, std::placeholders::_2));
                    }
                    else if (request_queue.size() == 1) // If already connected and this is the first request, start processing
                        write(request_queue.front().first->get_buffer(), std::bind(&client_session_base::on_write, self, std::placeholders::_1, std::placeholders::_2)); });
    }

    void client_session_base::on_connect(const asio::error_code &ec, const asio::ip::tcp::endpoint &)
    {
        if (ec)
        {
            LOG_ERR("Connection error: " << ec.message());
            return;
        }

        if (!request_queue.empty())
            write(request_queue.front().first->get_buffer(), std::bind(&client_session_base::on_write, shared_from_this(), std::placeholders::_1, std::placeholders::_2)); // Start writing the first request in the queue..
    }

    void client_session_base::on_write(const asio::error_code &ec, std::size_t)
    {
        callback_queue.emplace(std::move(request_queue.front().second)); // Move the callback from the front of the request queue to the callback queue..
        request_queue.pop();                                             // Remove the request from the queue after writing..
        if (ec)
        {
            LOG_ERR("Error on write: " << ec.message());
            return;
        }

        read_until(buffer, "\r\n\r\n", std::bind(&client_session_base::on_read_headers, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
    }

    void client_session_base::on_read_headers(const asio::error_code &ec, std::size_t bytes_transferred)
    {
        if (ec)
        {
            LOG_ERR("Error reading headers: " << ec.message());
            return;
        }

        // the buffer may contain additional bytes beyond the delimiter
        std::size_t additional_bytes = buffer.size() - bytes_transferred;

        current_response = std::make_unique<response>(buffer); // Create a new response object from the buffer..

        if (auto cl_i = current_response->headers.find("content-length"); cl_i != current_response->headers.end())
        { // If the response has a content-length header, read the body..
            std::size_t content_length = std::stoul(cl_i->second);
            if (content_length > additional_bytes) // If the content length is greater than the additional bytes, read the remaining body..
                read(buffer, content_length - additional_bytes, std::bind(&client_session_base::on_read_body, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
            else // If the buffer contains the entire body, process it immediately..
                on_read_body(ec, bytes_transferred);
        }
        else if (current_response->is_chunked())
            read_chunk(); // Handle chunked transfer encoding..
        else
        {
            callback_queue.front()(*current_response); // If no content-length or transfer-encoding, call the callback with the response..
            callback_queue.pop();                      // Remove the callback from the queue after processing..
            if (!request_queue.empty())
                write(request_queue.front().first->get_buffer(), std::bind(&client_session_base::on_write, shared_from_this(), std::placeholders::_1, std::placeholders::_2)); // Write the next request in the queue..
        }
    }
    void client_session_base::on_read_body(const std::error_code &ec, std::size_t)
    {
        if (ec == asio::error::eof)
        {
            LOG_DEBUG("Connection closed by server");
            return; // Connection closed by server, no further action needed..
        }
        else if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        if (current_response->accumulated_body.empty())
        {
            std::size_t content_length = std::stoul(current_response->headers.find("content-length")->second);
            std::string body;
            body.reserve(content_length);
            body.assign(asio::buffers_begin(buffer.data()), asio::buffers_begin(buffer.data()) + content_length);
            buffer.consume(content_length); // Consume the body from the buffer
            if (current_response->is_json())
                current_response = std::make_unique<json_response>(std::move(body), current_response->get_status_code(), std::move(current_response->headers), std::move(current_response->version)); // If the response is JSON, parse it..
            else
                current_response = std::make_unique<string_response>(std::move(body), current_response->get_status_code(), std::move(current_response->headers), std::move(current_response->version)); // Handle string response
        }
        else
        {
            if (current_response->is_json())
                current_response = std::make_unique<json_response>(std::move(current_response->accumulated_body), current_response->get_status_code(), std::move(current_response->headers), std::move(current_response->version)); // If the response is JSON, parse it..
            else
                current_response = std::make_unique<string_response>(std::move(current_response->accumulated_body), current_response->get_status_code(), std::move(current_response->headers), std::move(current_response->version)); // Handle string response
        }

        callback_queue.front()(*current_response); // Call the callback with the response..
        callback_queue.pop();                      // Remove the callback from the queue after processing..
        if (!request_queue.empty())
            write(request_queue.front().first->get_buffer(), std::bind(&client_session_base::on_write, shared_from_this(), std::placeholders::_1, std::placeholders::_2)); // Write the next request in the queue..
    }
    void client_session_base::read_chunk()
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
            if (size == 0) // If chunk size is 0, read the trailing CRLF
                read_until(buffer, "\r\n", [this, self](const std::error_code &ec, std::size_t bytes_transferred)
                                 {
                                     if (ec)
                                     {
                                         LOG_ERR("Error reading trailing CRLF: " << ec.message());
                                         return;
                                     }
                                     buffer.consume(2);                     // Consume the trailing CRLF
                                     on_read_body(ec, bytes_transferred); // Call on_read_body to process the response
                                 });
            else if (size > additional_bytes) // If chunk size is greater than additional bytes, read the remaining chunk
                read(buffer, size - additional_bytes, [this, self, size](const std::error_code &ec, std::size_t)
                           {
                               if (ec)
                               {
                                   LOG_ERR("Error reading chunk body: " << ec.message());
                                   return;
                               }
                               current_response->accumulated_body.reserve(current_response->accumulated_body.size() + size);
                               current_response->accumulated_body.append(asio::buffers_begin(buffer.data()), asio::buffers_begin(buffer.data()) + size);
                               buffer.consume(size + 2); // Consume the chunk body and the trailing CRLF
                               read_chunk();
                            });
            else 
                { // The buffer contains the entire chunk, append it to the body and read the next chunk
                    current_response->accumulated_body.reserve(current_response->accumulated_body.size() + size);
                    current_response->accumulated_body.append(asio::buffers_begin(buffer.data()), asio::buffers_begin(buffer.data()) + size);
                    buffer.consume(size + 2); // Consume the chunk body and the trailing CRLF
                    read_chunk(); // Read the next chunk
                } });
    }

    client_session::client_session(async_client_base &client, std::string_view host, unsigned short port, asio::ip::tcp::socket &&socket) : client_session_base(client, host, port), socket(std::move(socket)) {}
    client_session::~client_session()
    { // Ensure the session is disconnected when destroyed..
        if (is_connected())
            disconnect();
    }

    bool client_session::is_connected() const { return socket.is_open() && !connecting; }
    void client_session::disconnect()
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

        LOG_DEBUG("Disconnected from " << host << ":" << port);
    }
    void client_session::connect(asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, std::function<void(const asio::error_code &, const asio::ip::tcp::endpoint &)> callback)
    {
        connecting = true; // Set connecting to true to prevent multiple connection attempts
        asio::async_connect(socket, endpoints, [this, self = shared_from_this(), callback](const asio::error_code &ec, const asio::ip::tcp::endpoint &endpoint) mutable
                            {
                                if (ec)
                                    return callback(ec, endpoint);
                                LOG_DEBUG("Connected to " << endpoint);
                                connecting = false; // Reset connecting flag after successful connection
                                callback(ec, endpoint); }); // Call the callback with the endpoint
    }
    void client_session::read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read(socket, buffer, asio::transfer_exactly(size), callback); }
    void client_session::read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read_until(socket, buffer, delimiter, callback); }
    void client_session::write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_write(socket, buffer, callback); }

#ifdef ENABLE_SSL
    ssl_client_session::ssl_client_session(async_client_base &client, std::string_view host, unsigned short port, asio::ssl::stream<asio::ip::tcp::socket> &&socket) : client_session_base(client, host, port), socket(std::move(socket))
    {
        if (!SSL_set_tlsext_host_name(this->socket.native_handle(), host.data()))
        {
            LOG_ERR("SSL_set_tlsext_host_name failed");
            throw std::runtime_error("SSL_set_tlsext_host_name failed");
        }
    }
    ssl_client_session::~ssl_client_session()
    { // Ensure the session is disconnected when destroyed..
        if (is_connected())
            disconnect();
    }

    bool ssl_client_session::is_connected() const { return socket.next_layer().is_open() && !connecting; }
    void ssl_client_session::disconnect()
    {
        asio::error_code ec;

        // Gracefully shutdown the SSL connection
        socket.shutdown(ec);
        if (ec && ec != asio::ssl::error::stream_truncated)
            LOG_ERR("Error shutting down SSL connection: " << ec.message());

        // Shutdown the underlying socket
        socket.next_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        if (ec && ec != asio::error::eof && ec != asio::error::not_connected)
            LOG_ERR("Error shutting down socket: " << ec.message());

        // Close the socket
        socket.next_layer().close(ec);
        if (ec)
            LOG_ERR("Error closing socket: " << ec.message());

        LOG_DEBUG("Disconnected from " << host << ":" << port);
    }
    void ssl_client_session::connect(asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, std::function<void(const asio::error_code &, const asio::ip::tcp::endpoint &)> callback)
    {
        connecting = true; // Set connecting to true to prevent multiple connection attempts
        asio::async_connect(socket.next_layer(), endpoints, [this, self = shared_from_this(), callback](const asio::error_code &ec, const asio::ip::tcp::endpoint &endpoint) mutable
                            {
                                if (ec)
                                    return callback(ec, endpoint);
                                LOG_DEBUG("Connected to " << endpoint);
                                socket.set_verify_mode(asio::ssl::verify_peer);
                                socket.set_verify_callback(asio::ssl::host_name_verification(host));
                                socket.async_handshake(asio::ssl::stream_base::client, [this, self, callback, endpoint](const asio::error_code &ec)
                                    {
                                        if (ec)
                                        {
                                            LOG_ERR("SSL handshake failed: " << ec.message());
                                            return callback(ec, endpoint);
                                        }
                                        LOG_DEBUG("SSL handshake successful with " << endpoint);
                                        connecting = false; // Reset connecting flag after successful handshake
                                        callback(ec, endpoint); }); });
    }
    void ssl_client_session::read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read(socket, buffer, asio::transfer_exactly(size), callback); }
    void ssl_client_session::read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read_until(socket, buffer, delimiter, callback); }
    void ssl_client_session::write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_write(socket, buffer, callback); }
#endif
} // namespace network
