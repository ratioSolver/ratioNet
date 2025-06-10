#include "client_session.hpp"
#include "async_client.hpp"
#include "logging.hpp"

namespace network
{
    client_session_base::client_session_base(async_client_base &client, std::string_view host, unsigned short port) : client(client), host(host), port(port), resolver(client.io_ctx), endpoints(resolver.resolve(host, std::to_string(port))), strand(asio::make_strand(client.io_ctx)) {}
    client_session_base::~client_session_base() {}

    void client_session_base::send(std::unique_ptr<request> req, std::function<void(const response &)> &&cb)
    {
        asio::post(strand, [self = shared_from_this(), req = std::move(req), cb = std::move(cb)]() mutable
                   {
                    self->request_queue.emplace(std::move(req), std::move(cb));
                    if (!self->is_connected()) // If not connected, initiate connection..
                        self->connect(self->endpoints, std::bind(&client_session_base::on_connect, self, std::placeholders::_1, std::placeholders::_2));
                    else if (self->request_queue.size() == 1) // If already connected and this is the first request, start processing
                        self->write(self->request_queue.front().first->get_buffer(), std::bind(&client_session_base::on_write, self, std::placeholders::_1, std::placeholders::_2)); });
    }

    void client_session_base::on_connect(const asio::error_code &ec, const asio::ip::tcp::endpoint &endpoint)
    {
        if (ec)
        {
            LOG_ERR("Connection error: " << ec.message());
            return;
        }
        LOG_INFO("Connected to " << endpoint);
        if (!request_queue.empty())
            write(request_queue.front().first->get_buffer(), std::bind(&client_session_base::on_write, shared_from_this(), std::placeholders::_1, std::placeholders::_2)); // Start writing the first request in the queue..
    }

    void client_session_base::on_write(const asio::error_code &ec, std::size_t)
    {
        auto cb = std::move(request_queue.front().second); // Get the callback for the current request..
        request_queue.pop();                               // Remove the request from the queue after writing..
        if (ec)
        {
            LOG_ERR("Error on write: " << ec.message());
            return;
        }
        if (!request_queue.empty())
            write(request_queue.front().first->get_buffer(), std::bind(&client_session_base::on_write, shared_from_this(), std::placeholders::_1, std::placeholders::_2)); // Write the next request in the queue..

        response_queue.emplace(std::make_unique<response>(), std::move(cb)); // Prepare a response object for the next read operation..
        if (response_queue.size() == 1)                                      // If this is the first response, start reading headers..
            read_until(response_queue.front().first->buffer, "\r\n\r\n", std::bind(&client_session_base::on_read_headers, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
    }

    void client_session_base::on_read_headers(const asio::error_code &ec, std::size_t bytes_transferred)
    {
        if (ec)
        {
            LOG_ERR("Error reading headers: " << ec.message());
            return;
        }

        auto &res = *response_queue.front().first; // Get the current response object..

        // the buffer may contain additional bytes beyond the delimiter
        std::size_t additional_bytes = res.buffer.size() - bytes_transferred;

        res.parse(); // Parse the headers from the buffer..

        if (res.headers.find("content-length") != res.headers.end())
        { // If the response has a content-length header, read the body..
            std::size_t content_length = std::stoul(res.headers["content-length"]);
            if (content_length > additional_bytes) // If the content length is greater than the additional bytes, read the remaining body..
                read(res.buffer, content_length - additional_bytes, std::bind(&client_session_base::on_read_body, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
            else // If the buffer contains the entire body, process it immediately..
                on_read_body(ec, bytes_transferred);
        }
        else if (res.headers.find("transfer-encoding") != res.headers.end() && res.headers.at("transfer-encoding") == "chunked")
            read_chunk(); // Handle chunked transfer encoding..
        else
            response_queue.front().second(res); // Call the callback with the response..
    }
    void client_session_base::on_read_body(const std::error_code &ec, std::size_t)
    {
        if (ec == asio::error::eof)
            return; // connection closed by client
        else if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        auto &res = response_queue.front().first; // Get the current response object..
        if (res->headers.find("content-type") != res->headers.end() && res->headers["content-type"].find("application/json") != std::string::npos)
        {
            if (!res->accumulated_body.empty())
                res = std::make_unique<json_response>(json::load(res->accumulated_body), res->get_status_code(), std::move(res->headers), std::move(res->version)); // If the response is JSON, parse it..
            else
            {
                std::istream is(&res->buffer);
                res = std::make_unique<json_response>(json::load(is), res->get_status_code(), std::move(res->headers), std::move(res->version));
            }
        }
        else
        {
            if (!res->accumulated_body.empty())
                res = std::make_unique<string_response>(std::move(res->accumulated_body), res->get_status_code(), std::move(res->headers), std::move(res->version)); // If the response is a string, use the accumulated body..
            else
            {
                std::string body;
                body.reserve(res->buffer.size());
                body.assign(asio::buffers_begin(res->buffer.data()), asio::buffers_end(res->buffer.data()));
                res = std::make_unique<string_response>(std::move(body), res->get_status_code(), std::move(res->headers), std::move(res->version)); // Handle string response
            }
        }

        response_queue.front().second(*res); // Call the callback with the response..

        response_queue.pop(); // Remove the response from the queue after processing..
        if (!response_queue.empty())
            read_until(response_queue.front().first->buffer, "\r\n\r\n", std::bind(&client_session_base::on_read_headers, shared_from_this(), std::placeholders::_1, std::placeholders::_2)); // Start reading the next response headers..
    }
    void client_session_base::read_chunk()
    {
        read_until(response_queue.front().first->buffer, "\r\n", [self = shared_from_this()](const std::error_code &ec, std::size_t bytes_transferred)
                   {
            if (ec)
            {
                LOG_ERR("Error reading chunk: " << ec.message());
                return;
            }
            
            auto &res = *self->response_queue.front().first; // Get the current response object..

            // The buffer may contain additional bytes beyond the delimiter
            std::size_t additional_bytes = res.buffer.size() - bytes_transferred;

            std::string chunk_size;
            std::vector<std::string> extensions;
            std::istream is(&res.buffer);
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
                self->read_until(res.buffer, "\r\n", [self, &res](const std::error_code &ec, std::size_t bytes_transferred)
                                 {
                                     if (ec)
                                     {
                                         LOG_ERR("Error reading trailing CRLF: " << ec.message());
                                         return;
                                     }
                                     res.buffer.consume(2);                     // Consume the trailing CRLF
                                     self->on_read_body(ec, bytes_transferred); // Call on_read_body to process the response
                                 });
            else if (size > additional_bytes) // If chunk size is greater than additional bytes, read the remaining chunk
                self->read(res.buffer, size - additional_bytes, [self, size, &res](const std::error_code &ec, std::size_t)
                           {
                               if (ec)
                               {
                                   LOG_ERR("Error reading chunk body: " << ec.message());
                                   return;
                               }
                               res.accumulated_body.reserve(res.accumulated_body.size() + size);
                               res.accumulated_body.append(asio::buffers_begin(res.buffer.data()), asio::buffers_begin(res.buffer.data()) + size);
                               res.buffer.consume(size + 2); // Consume the chunk body and the trailing CRLF
                               self->read_chunk();
                            });
            else 
                { // The buffer contains the entire chunk, append it to the body and read the next chunk
                    res.accumulated_body.reserve(res.accumulated_body.size() + size);
                    res.accumulated_body.append(asio::buffers_begin(res.buffer.data()), asio::buffers_begin(res.buffer.data()) + size);
                    res.buffer.consume(size + 2); // Consume the chunk body and the trailing CRLF
                    self->read_chunk(); // Read the next chunk
                } });
    }

    client_session::client_session(async_client_base &client, std::string_view host, unsigned short port, asio::ip::tcp::socket &&socket) : client_session_base(client, host, port), socket(std::move(socket)) {}

    bool client_session::is_connected() const { return socket.is_open(); }
    void client_session::connect(asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, std::function<void(const asio::error_code &, const asio::ip::tcp::endpoint &)> callback) { asio::async_connect(socket, endpoints, callback); }
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

    bool ssl_client_session::is_connected() const { return socket.next_layer().is_open(); }
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
