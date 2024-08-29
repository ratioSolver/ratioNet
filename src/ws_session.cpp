#include "ws_session.hpp"
#include "server.hpp"
#include "logging.hpp"

namespace network
{
#ifdef ENABLE_SSL
    ws_session::ws_session(server &srv, const std::string &path, asio::ssl::stream<asio::ip::tcp::socket> &&socket) : srv(srv), path(path), endpoint(socket.lowest_layer().remote_endpoint()), socket(std::move(socket)) { LOG_TRACE("WebSocket session created with " << endpoint); }
#else
    ws_session::ws_session(server &srv, const std::string &path, asio::ip::tcp::socket &&socket) : srv(srv), path(path), endpoint(socket.remote_endpoint()), socket(std::move(socket)) { LOG_TRACE("WebSocket session created with " << endpoint); }
#endif
    ws_session::~ws_session() { LOG_TRACE("WebSocket session destroyed with " << endpoint); }

    void ws_session::start()
    {
        srv.on_connect(*this);
        read();
    }

    void ws_session::read()
    {
        msg = std::make_unique<message>();
        asio::async_read(socket, msg->buffer, asio::transfer_exactly(2), std::bind(&ws_session::on_read, shared_from_this(), asio::placeholders::error, asio::placeholders::bytes_transferred));
    }

    void ws_session::enqueue(std::unique_ptr<message> res)
    {
        asio::post(socket.get_executor(), [self = shared_from_this(), r = std::move(res)]() mutable
                   { self->res_queue.push(std::move(r));
                            if (self->res_queue.size() == 1)
                                self->write(); });
    }

    void ws_session::write() { asio::async_write(socket, res_queue.front()->get_buffer(), std::bind(&ws_session::on_write, shared_from_this(), asio::placeholders::error, asio::placeholders::bytes_transferred)); }

    void ws_session::on_read(const std::error_code &ec, std::size_t bytes_transferred)
    { // read the first two bytes of the message (opcode and length)
        if (ec == asio::error::eof)
        { // connection closed by client
            srv.on_disconnect(*this);
            return;
        }
        else if (ec)
        {
            LOG_ERR(ec.message());
            srv.on_error(*this, ec);
            return;
        }

        std::istream is(&msg->buffer);
        is.read(reinterpret_cast<char *>(&msg->fin_rsv_opcode), 1);

        char len; // second byte of the message
        is.read(&len, 1);
        size_t length = len & 0x7F; // length of the payload
        if (length == 126)
            asio::async_read(socket, msg->buffer, asio::transfer_exactly(2), [self = shared_from_this()](const std::error_code &ec, std::size_t bytes_transferred)
                             { char buf[2];
                                      std::istream is(&self->msg->buffer);
                                      is.read(buf, 2);
                                      size_t length = (buf[0] << 8) | buf[1];
                                      asio::async_read(self->socket, self->msg->buffer, asio::transfer_exactly(length + 4), std::bind(&ws_session::on_message, self, asio::placeholders::error, asio::placeholders::bytes_transferred)); });
        else if (length == 127)
            asio::async_read(socket, msg->buffer, asio::transfer_exactly(8), [self = shared_from_this()](const std::error_code &ec, std::size_t bytes_transferred)
                             { char buf[8];
                                      std::istream is(&self->msg->buffer);
                                      is.read(buf, 8);
                                      size_t length = 0;
                                      for (size_t i = 0; i < 8; i++)
                                          length = (length << 8) | buf[i];
                                      asio::async_read(self->socket, self->msg->buffer, asio::transfer_exactly(length + 4), std::bind(&ws_session::on_message, self, asio::placeholders::error, asio::placeholders::bytes_transferred)); });
        else
            asio::async_read(socket, msg->buffer, asio::transfer_exactly(length + 4), std::bind(&ws_session::on_message, shared_from_this(), asio::placeholders::error, asio::placeholders::bytes_transferred));
    }

    void ws_session::on_message(const std::error_code &ec, std::size_t bytes_transferred)
    { // read the rest of the message (mask and payload)
        if (ec == asio::error::eof)
        { // connection closed by client
            srv.on_disconnect(*this);
            return;
        }
        else if (ec)
        {
            LOG_ERR(ec.message());
            srv.on_error(*this, ec);
            return;
        }

        std::istream is(&msg->buffer);
        char mask[4]; // mask for the message
        is.read(mask, 4);
        for (size_t i = 0; i < bytes_transferred - 4; i++) // unmask the message
            *msg->payload += is.get() ^ mask[i % 4];

        if (msg->fin_rsv_opcode & 0x80) // fin bit is set
            srv.on_message(*this, std::move(msg));

        read(); // read the next message
    }

    void ws_session::on_write(const std::error_code &ec, std::size_t bytes_transferred)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            while (!res_queue.empty()) // clear the response queue
                res_queue.pop();
            srv.on_error(*this, ec);
            return;
        }

        res_queue.pop();
        if (!res_queue.empty())
            write(); // write the next message
    }
} // namespace network