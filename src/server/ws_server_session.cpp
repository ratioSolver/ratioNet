#include "ws_server_session.hpp"
#include "server.hpp"
#include "logging.hpp"

namespace network
{
    ws_server_session_base::ws_server_session_base(server_base &server, std::string_view path, asio::any_io_executor executor) : server(server), path(path), executor(executor) {}
    ws_server_session_base::~ws_server_session_base() { LOG_TRACE("WebSocket server session destroyed"); }

    void ws_server_session_base::run()
    {
        LOG_TRACE("WebSocket server session started");
        incoming_messages.emplace(std::make_unique<message>());
        // Start reading the first two bytes to determine the message type and size
        read(incoming_messages.front()->get_buffer(), 2, std::bind(&ws_server_session_base::on_read, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
    }

    void ws_server_session_base::enqueue(std::unique_ptr<message> msg)
    {
        asio::post(executor, [this, self = shared_from_this(), msg = std::move(msg)]() mutable
                   {
                       outgoing_messages.emplace(std::move(msg));
                       if (outgoing_messages.size() == 1)
                           write(outgoing_messages.front()->get_buffer(), std::bind(&ws_server_session_base::on_write, self, std::placeholders::_1, std::placeholders::_2)); });
    }

    void ws_server_session_base::on_read(const asio::error_code &ec, std::size_t)
    {
        if (ec == asio::error::eof)
        { // connection closed by client
            server.on_disconnect(*this);
            return;
        }
        else if (ec)
        {
            LOG_ERR(ec.message());
            server.on_error(*this, ec);
            return;
        }

        auto &msg = incoming_messages.front();

        std::istream is(&msg->buffer);
        is.read(reinterpret_cast<char *>(&msg->fin_rsv_opcode), 1);

        char len; // second byte of the message
        is.read(&len, 1);
        size_t length = len & 0x7F; // length of the payload
        if (length == 126)
            read(msg->buffer, 2, [self = shared_from_this(), &msg](const std::error_code &, std::size_t)
                 { char buf[2];
                                      std::istream is(&msg->buffer);
                                      is.read(buf, 2);
                                      size_t length = (buf[0] << 8) | buf[1];
                                      self->read(msg->buffer, length + 4, std::bind(&ws_server_session_base::on_message, self, asio::placeholders::error, asio::placeholders::bytes_transferred)); });
        else if (length == 127)
            read(msg->buffer, 8, [self = shared_from_this(), &msg](const std::error_code &, std::size_t)
                 { char buf[8];
                                      std::istream is(&msg->buffer);
                                      is.read(buf, 8);
                                      size_t length = 0;
                                      for (size_t i = 0; i < 8; i++)
                                          length = (length << 8) | buf[i];
                                      self->read(msg->buffer, length + 4, std::bind(&ws_server_session_base::on_message, self, asio::placeholders::error, asio::placeholders::bytes_transferred)); });
        else
            read(msg->buffer, length + 4, std::bind(&ws_server_session_base::on_message, shared_from_this(), asio::placeholders::error, asio::placeholders::bytes_transferred));
    }

    void ws_server_session_base::on_message(const asio::error_code &ec, std::size_t bytes_transferred)
    {
        if (ec == asio::error::eof)
        { // connection closed by client
            server.on_disconnect(*this);
            return;
        }
        else if (ec)
        {
            LOG_ERR(ec.message());
            server.on_error(*this, ec);
            return;
        }

        auto &msg = incoming_messages.front();
        std::istream is(&msg->buffer);
        char mask[4]; // mask for the message
        is.read(mask, 4);
        for (size_t i = 0; i < bytes_transferred - 4; i++) // unmask the message
            *msg->payload += is.get() ^ mask[i % 4];

        server.on_message(*this, *msg);
        incoming_messages.pop();
        if (!incoming_messages.empty())
            read(incoming_messages.front()->get_buffer(), 2, std::bind(&ws_server_session_base::on_read, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
    }

    void ws_server_session_base::on_write(const asio::error_code &ec, std::size_t)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            server.on_error(*this, ec);
            return;
        }

        // Remove the message from the queue after successful write
        outgoing_messages.pop();
        if (!outgoing_messages.empty())
            write(outgoing_messages.front()->get_buffer(), std::bind(&ws_server_session_base::on_write, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
    }

    ws_server_session::ws_server_session(server_base &server, std::string_view path, asio::ip::tcp::socket &&socket) : ws_server_session_base(server, path, socket.get_executor()), socket(std::move(socket)) {}

    void ws_server_session::read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read(socket, buffer, asio::transfer_exactly(size), std::move(callback)); }
    void ws_server_session::write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_write(socket, buffer, std::move(callback)); }

#ifdef ENABLE_SSL
    wss_server_session::wss_server_session(server_base &server, std::string_view path, asio::ssl::stream<asio::ip::tcp::socket> &&socket) : ws_server_session_base(server, path, socket.get_executor()), socket(std::move(socket)) {}

    void wss_server_session::read(asio::streambuf &buffer, std::size_t size, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_read(socket, buffer, asio::transfer_exactly(size), std::move(callback)); }
    void wss_server_session::write(asio::streambuf &buffer, std::function<void(const std::error_code &, std::size_t)> callback) { asio::async_write(socket, buffer, std::move(callback)); }
#endif
} // namespace network
