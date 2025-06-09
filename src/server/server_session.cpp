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

    void server_session_base::run()
    {
        request_queue.emplace(std::make_unique<request>());
        if (request_queue.size() == 1) // If this is the first request, start reading headers
            read_until(get_next_request().get_buffer(), "\r\n\r\n", std::bind(&server_session_base::on_read_headers, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
    }

    void server_session_base::upgrade()
    {
        auto &req = get_next_request(); // Get the current request object

        auto key_it = req.headers.find("sec-websocket-key");
        if (key_it == req.headers.end())
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
        response_queue.emplace(std::make_unique<response>(status_code::websocket_switching_protocols, std::map<std::string, std::string>{{"Upgrade", "websocket"}, {"Connection", "Upgrade"}, {"Sec-WebSocket-Accept", key}}));
        write(get_next_response().get_buffer(), std::bind(&server_session_base::on_upgrade, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
    }

    void server_session_base::enqueue(std::unique_ptr<response> res)
    {
        asio::post(strand, [this, self = shared_from_this(), res = std::move(res)]() mutable
                   { response_queue.emplace(std::move(res));
                     if (response_queue.size() == 1) // If this is the first response, start writing
                         write(get_next_response().get_buffer(), std::bind(&server_session_base::on_write, shared_from_this(), std::placeholders::_1, std::placeholders::_2)); });
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

        auto &req = get_next_request(); // Get the current request object

        // the buffer may contain additional bytes beyond the delimiter
        std::size_t additional_bytes = req.get_buffer().size() - bytes_transferred;

        req.parse(); // parse the request line and headers

        if (req.is_upgrade()) // handle websocket upgrade request
            return upgrade();

        if (req.headers.find("content-length") != req.headers.end())
        { // read body
            std::size_t content_length = std::stoul(req.headers["content-length"]);
            if (content_length > additional_bytes) // read the remaining body
                read(req.buffer, content_length - additional_bytes, std::bind(&server_session_base::on_read_body, shared_from_this(), asio::placeholders::error, asio::placeholders::bytes_transferred));
            else // the buffer contains the entire body
                on_read_body(ec, bytes_transferred);
        }
        else if (req.headers.find("transfer-encoding") != req.headers.end() && req.headers.at("transfer-encoding") == "chunked")
            read_chunk();
        else // no body
            server.handle_request(*this, req);
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

        auto &req = request_queue.front(); // Get the current request object

        std::istream is(&req->buffer);
        if (req->headers.find("content-type") != req->headers.end() && req->headers["content-type"].find("application/json") != std::string::npos)
            req = std::make_unique<json_request>(req->v, std::move(req->target), std::move(req->version), std::move(req->headers), json::load(is));
        else
        {
            std::string body;
            body.reserve(req->buffer.size());
            body.assign(asio::buffers_begin(req->buffer.data()), asio::buffers_end(req->buffer.data()));
            req = std::make_unique<string_request>(req->v, std::move(req->target), std::move(req->version), std::move(req->headers), std::move(body));
        }

        server.handle_request(*this, *req);
    }
    void server_session_base::read_chunk(std::string body)
    {
        auto &req = get_next_request(); // Get the current request object
        read_until(req.get_buffer(), "\r\n", [self = shared_from_this(), body = std::move(body), &req](const std::error_code &ec, std::size_t bytes_transferred)
                   {
            if (ec)
            {
                LOG_ERR("Error reading chunk: " << ec.message());
                return;
            }

            // The buffer may contain additional bytes beyond the delimiter
            std::size_t additional_bytes = req.get_buffer().size() - bytes_transferred;

            std::string chunk_size_str(asio::buffers_begin(req.buffer.data()), asio::buffers_begin(req.buffer.data()) + bytes_transferred);
            req.buffer.consume(bytes_transferred); // Remove the chunk size from the buffer..

            std::size_t chunk_size = std::stoul(chunk_size_str, nullptr, 16); // Convert chunk size from hex to decimal
            if (chunk_size == 0)                                              // If chunk size is 0, read the trailing CRLF
                self->read_until(req.buffer, "\r\n", [self, &req](const std::error_code &ec, std::size_t bytes_transferred)
                                 {
                                     if (ec)
                                     {
                                         LOG_ERR("Error reading trailing CRLF: " << ec.message());
                                         return;
                                     }
                                     req.buffer.consume(2); // Consume the trailing CRLF
                                     self->on_read_body(ec, bytes_transferred);             // Call on_read_body to process the response
                                 });
            else if (chunk_size > additional_bytes) // If chunk size is greater than additional bytes, read the remaining chunk
                self->read(req.buffer, chunk_size - additional_bytes, [self, chunk_size, body = std::move(body), &req](const std::error_code &ec, std::size_t)
                           {
                               if (ec)
                               {
                                   LOG_ERR("Error reading chunk body: " << ec.message());
                                   return;
                               }
                               std::string chunk_body(asio::buffers_begin(req.buffer.data()), asio::buffers_begin(req.buffer.data()) + chunk_size);
                               self->read_chunk(body+chunk_body);                                     // Read the next chunk
                           });
            else 
                { // The buffer contains the entire chunk, append it to the body and read the next chunk
                    std::string chunk_body(asio::buffers_begin(req.buffer.data()), asio::buffers_begin(req.buffer.data()) + chunk_size);
                    req.buffer.consume(2); // Consume the chunk body and the trailing CRLF
                    self->read_chunk(body + chunk_body); // Read the next chunk
                } });
    }

    server_session::server_session(server_base &server, asio::ip::tcp::socket &&socket) : server_session_base(server), socket(std::move(socket)) {}

    void server_session::on_upgrade(const asio::error_code &ec, std::size_t)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
        // the upgrade response has been sent, now we can start a WebSocket session
        std::make_shared<ws_server_session>(get_server(), get_next_request().get_target(), std::move(socket))->run();
    }

    void server_session::read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read(socket, buffer, asio::transfer_exactly(size), callback); }
    void server_session::read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read_until(socket, buffer, delimiter, callback); }
    void server_session::write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_write(socket, buffer, callback); }

#ifdef ENABLE_SSL
    ssl_server_session::ssl_server_session(server_base &server, asio::ssl::stream<asio::ip::tcp::socket> &&socket) : server_session_base(server), socket(std::move(socket)) {}

    void ssl_server_session::handshake(std::function<void(const std::error_code &)> callback) { socket.async_handshake(asio::ssl::stream_base::server, callback); }

    void ssl_server_session::on_upgrade(const asio::error_code &ec, std::size_t)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
        // the upgrade response has been sent, now we can start a WebSocket session
        std::make_shared<wss_server_session>(get_server(), get_next_request().get_target(), std::move(socket))->run();
    }

    void ssl_server_session::read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read(socket, buffer, asio::transfer_exactly(size), callback); }
    void ssl_server_session::read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read_until(socket, buffer, delimiter, callback); }
    void ssl_server_session::write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_write(socket, buffer, callback); }
#endif
} // namespace network
