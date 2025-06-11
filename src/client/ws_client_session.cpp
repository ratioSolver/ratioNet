#include "ws_client_session.hpp"
#include "async_client.hpp"
#include "base64.hpp"
#include "logging.hpp"

namespace network
{
    ws_client_session_base::ws_client_session_base(async_client_base &client, std::string_view host, unsigned short port, std::string_view target, asio::any_io_executor executor) : client(client), host(host), port(port), target(target), executor(executor), resolver(client.io_ctx), endpoints(resolver.resolve(host, std::to_string(port))) {}
    ws_client_session_base::~ws_client_session_base() {}

    void ws_client_session_base::enqueue(std::unique_ptr<message> msg)
    {
        asio::post(executor, [this, self = shared_from_this(), msg = std::move(msg)]() mutable
                   {
                    outgoing_messages.emplace(std::move(msg));
                    if (!is_connected())
                    {
                        if (!is_connecting()) // If not already connecting, initiate a connection
                            connect();
                    }
                    else if (outgoing_messages.size() == 1) // If already connected and this is the first message, start writing
                        write(outgoing_messages.front()->get_buffer(), std::bind(&ws_client_session_base::on_write, self, std::placeholders::_1, std::placeholders::_2)); });
    }

    void ws_client_session_base::connect()
    {
        asio::post(executor, [this, self = shared_from_this()]()
                   {
                    if (!is_connecting()) // If not already connecting, initiate a connection
                        connect(endpoints, std::bind(&ws_client_session_base::on_connect, self, std::placeholders::_1, std::placeholders::_2)); });
    }

    void ws_client_session_base::on_connect(const asio::error_code &ec, [[maybe_unused]] const asio::ip::tcp::endpoint &endpoint)
    {
        if (ec)
        {
            LOG_ERR("Connection error: " << ec.message());
            return;
        }
        LOG_DEBUG("Connected to " << endpoint);

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
        write(req->get_buffer(), [this, self = shared_from_this(), req](const std::error_code &ec, std::size_t)
              {
            if (ec)
            {
                LOG_ERR("Error sending handshake request: " << ec.message());
                return;
            }

            auto res = std::make_shared<response>();
            read_until(res->buffer, "\r\n\r\n", [this, self, res](const std::error_code &ec, std::size_t)
            {
                if (ec)
                {
                    LOG_ERR("Error reading handshake response: " << ec.message());
                    return;
                }

                // Parse the response
                res->parse();
                if (res->get_status_code() != status_code::websocket_switching_protocols)
                {
                    LOG_ERR("Handshake failed with status code: " << res->get_status_code());
                    return;
                }

                LOG_DEBUG("Handshake successful, connected to " << host << ":" << port);
                if (on_open_handler)
                    on_open_handler(); // Call the on_open handler if set.

                // Start reading messages from the WebSocket server.
                incoming_messages.emplace(std::make_unique<message>());
                // Start reading the first two bytes to determine the message type and size
                read(incoming_messages.front()->buffer, 2, std::bind(&ws_client_session_base::on_read, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
                // If there are any messages to send, start writing them.
                if (!outgoing_messages.empty())
                    write(outgoing_messages.front()->get_buffer(), std::bind(&ws_client_session_base::on_write, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
            }); });
    }

    void ws_client_session_base::on_read(const asio::error_code &ec, std::size_t)
    {
        if (ec == asio::error::eof)
        { // Connection closed by the server
            LOG_DEBUG("Connection closed by the server");
            if (on_close_handler)
                on_close_handler();
            return;
        }
        else if (ec)
        {
            LOG_ERR("Error reading from socket: " << ec.message());
            if (on_error_handler)
                on_error_handler(ec);
            return;
        }

        auto &msg = incoming_messages.front();
        std::istream is(&msg->buffer);
        is.read(reinterpret_cast<char *>(&msg->fin_rsv_opcode), 1);

        char len; // second byte of the message
        is.read(&len, 1);
        size_t length = len & 0x7F; // length of the payload
        if (length == 126)          // Extended payload length
            read(msg->buffer, 2, [this, self = shared_from_this(), &msg](const std::error_code &, std::size_t)
                 {
                    char buf[2];
                    std::istream is(&msg->buffer);
                    is.read(buf, 2);
                    size_t length = (buf[0] << 8) | buf[1];
                    read(msg->buffer, length, std::bind(&ws_client_session_base::on_message, self, std::placeholders::_1, std::placeholders::_2)); });
        else if (length == 127) // Extended payload length (64-bit)
            read(msg->buffer, 8, [this, self = shared_from_this(), &msg](const std::error_code &, std::size_t)
                 {
                    char buf[8];
                    std::istream is(&msg->buffer);
                    is.read(buf, 8);
                    size_t length = 0;
                    for (size_t i = 0; i < 8; i++)
                        length = (length << 8) | buf[i];
                    read(msg->buffer, length, std::bind(&ws_client_session_base::on_message, self, std::placeholders::_1, std::placeholders::_2)); });
        else // Normal payload length
            read(msg->buffer, length, std::bind(&ws_client_session_base::on_message, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
    }

    void ws_client_session_base::on_message(const asio::error_code &ec, std::size_t bytes_transferred)
    { // read the rest of the message (mask and payload)
        if (ec == asio::error::eof)
        { // connection closed by client
            on_close_handler();
            return;
        }
        else if (ec)
        {
            LOG_ERR(ec.message());
            on_error_handler(ec);
            return;
        }

        auto &msg = incoming_messages.front();

        std::istream is(&msg->buffer);
        std::vector<char> data(bytes_transferred);
        is.read(data.data(), bytes_transferred);
        msg->payload->append(data.data(), bytes_transferred);

        on_message_handler(*msg);

        // Remove the processed message
        incoming_messages.pop();
        // Read the next message
        incoming_messages.emplace(std::make_unique<message>());

        read(incoming_messages.front()->buffer, 2, std::bind(&ws_client_session_base::on_read, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
    }

    void ws_client_session_base::on_write(const asio::error_code &ec, [[maybe_unused]] std::size_t bytes_transferred)
    {
        if (ec)
        {
            LOG_ERR("Error writing to socket: " << ec.message());
            if (on_error_handler)
                on_error_handler(ec);
            return;
        }

        LOG_TRACE("Sent " << bytes_transferred << " bytes");

        // Remove the message from the outgoing queue
        outgoing_messages.pop();

        // If there are more messages to send, write the next one
        if (!outgoing_messages.empty())
            write(outgoing_messages.front()->get_buffer(), std::bind(&ws_client_session_base::on_write, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
    }

    ws_client_session::ws_client_session(async_client_base &client, std::string_view host, unsigned short port, std::string_view target, asio::ip::tcp::socket &&socket) : ws_client_session_base(client, host, port, target, socket.get_executor()), socket(std::move(socket)) {}
    ws_client_session::~ws_client_session()
    { // Ensure the session is disconnected when destroyed.
        if (is_connected())
            disconnect();
    }

    bool ws_client_session::is_connected() const { return socket.is_open() && !connecting; }

    void ws_client_session::disconnect()
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

    void ws_client_session::connect(asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, std::function<void(const asio::error_code &, const asio::ip::tcp::endpoint &)> callback)
    {
        connecting = true; // Set the connecting flag to true before starting the connection
        asio::async_connect(socket, endpoints, [this, self = shared_from_this(), callback](const asio::error_code &ec, const asio::ip::tcp::endpoint &endpoint) mutable
                            {
                                if (ec)
                                    return callback(ec, endpoint);
                                LOG_DEBUG("Connected to " << endpoint);
                                connecting = false; // Reset connecting flag after successful connection
                                callback(ec, endpoint); });
    }

    void ws_client_session::read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read(socket, buffer, asio::transfer_exactly(size), callback); }
    void ws_client_session::read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read_until(socket, buffer, delimiter, callback); }
    void ws_client_session::write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_write(socket, buffer, callback); }

#ifdef ENABLE_SSL
    wss_client_session::wss_client_session(async_client_base &client, std::string_view host, unsigned short port, std::string_view target, asio::ssl::stream<asio::ip::tcp::socket> &&socket) : ws_client_session_base(client, host, port, target, socket.get_executor()), socket(std::move(socket))
    {
        if (!SSL_set_tlsext_host_name(socket.native_handle(), host.data()))
        {
            LOG_ERR("SSL_set_tlsext_host_name failed");
            throw std::runtime_error("SSL_set_tlsext_host_name failed");
        }
    }
    wss_client_session::~wss_client_session()
    { // Ensure the session is disconnected when destroyed.
        if (is_connected())
            disconnect();
    }

    bool wss_client_session::is_connected() const { return socket.next_layer().is_open() && !connecting; }

    void wss_client_session::disconnect()
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

    void wss_client_session::connect(asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints, std::function<void(const asio::error_code &, const asio::ip::tcp::endpoint &)> callback)
    {
        connecting = true; // Set the connecting flag to true before starting the connection
        asio::async_connect(socket.next_layer(), endpoints, [this, self = shared_from_this(), callback](const asio::error_code &ec, const asio::ip::tcp::endpoint &endpoint) mutable
                            {
                                if (ec)
                                    return callback(ec, endpoint);
                                LOG_DEBUG("Connected to " << endpoint);
                                socket.set_verify_mode(asio::ssl::verify_peer);
                                socket.set_verify_callback(asio::ssl::host_name_verification(host));
                                socket.async_handshake(asio::ssl::stream_base::client, [this, self, callback, &endpoint](const asio::error_code &ec)
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

    void wss_client_session::read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read(socket.next_layer(), buffer, asio::transfer_exactly(size), callback); }
    void wss_client_session::read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read_until(socket.next_layer(), buffer, delimiter, callback); }
    void wss_client_session::write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_write(socket.next_layer(), buffer, callback); }
#endif
} // namespace network
