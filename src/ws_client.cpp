#include "ws_client.hpp"
#include "logging.hpp"

namespace network
{
#ifdef ENABLE_SSL
    ws_client::ws_client(const std::string &host, unsigned short port, std::function<void()> on_open_handler, std::function<void(std::string_view)> on_message_handler, std::function<void()> on_close_handler, std::function<void(const std::error_code &)> on_error_handler) : host(host), port(port), on_open_handler(on_open_handler), on_message_handler(on_message_handler), on_close_handler(on_close_handler), on_error_handler(on_error_handler), resolver(io_ctx), socket(io_ctx, ctx), strand(asio::make_strand(io_ctx)) { connect(); }
#else
    ws_client::ws_client(const std::string &host, unsigned short port, std::function<void()> on_open_handler, std::function<void(std::string_view)> on_message_handler, std::function<void()> on_close_handler, std::function<void(const std::error_code &)> on_error_handler) : host(host), port(port), on_open_handler(on_open_handler), on_message_handler(on_message_handler), on_close_handler(on_close_handler), on_error_handler(on_error_handler), resolver(io_ctx), socket(io_ctx), strand(asio::make_strand(io_ctx)) { connect(); }
#endif
    ws_client::~ws_client() { LOG_TRACE("WebSocket client destroyed"); }

    void ws_client::enqueue(utils::u_ptr<message> msg)
    {
        asio::post(strand, [this, m = std::move(msg)]() mutable
                   { res_queue.push(std::move(m));
                            if (res_queue.size() == 1)
                                write(); });
    }

    void ws_client::connect()
    {
        LOG_DEBUG("Connecting to host " + host + ":" + std::to_string(port));
        auto query = asio::ip::tcp::resolver::query(host, std::to_string(port));
        resolver.async_resolve(query, std::bind(&ws_client::on_resolve, this, asio::placeholders::error, asio::placeholders::results));
        io_ctx.run();
    }

#ifdef ENABLE_SSL
    void ws_client::handshake() { socket.async_handshake(asio::ssl::stream_base::client, std::bind(&ws_client::on_handshake, this, asio::placeholders::error)); }

    void ws_client::on_handshake(const std::error_code &ec)
    {
        if (ec == asio::ssl::error::stream_truncated)
            return; // connection closed by client
        else if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        on_open_handler();
        read();
    }
#endif

    void ws_client::read()
    {
        msg = utils::make_u_ptr<message>();
        asio::async_read(socket, msg->buffer, asio::transfer_exactly(2), std::bind(&ws_client::on_read, this, asio::placeholders::error, asio::placeholders::bytes_transferred));
    }

    void ws_client::write() { asio::async_write(socket, res_queue.front()->get_buffer(), std::bind(&ws_client::on_write, this, asio::placeholders::error, asio::placeholders::bytes_transferred)); }

    void ws_client::on_resolve(const std::error_code &ec, asio::ip::tcp::resolver::results_type results)
    {
        if (ec)
        {
            LOG_ERR("Failed to resolve host: " + ec.message());
            return;
        }

#ifdef ENABLE_SSL
        asio::async_connect(socket.lowest_layer(), results, std::bind(&ws_client::on_connect, this, asio::placeholders::error));
#else
        asio::async_connect(socket, results, std::bind(&ws_client::on_connect, this, asio::placeholders::error));
#endif
    }

    void ws_client::on_connect(const std::error_code &)
    {
        LOG_DEBUG("Connected to host " + host + ":" + std::to_string(port));
#ifdef ENABLE_SSL
        handshake();
#else
        on_open_handler();
        read();
#endif
    }

    void ws_client::on_write(const std::error_code &ec, std::size_t)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        res_queue.pop();
        if (!res_queue.empty())
            write(); // write the next message
    }

    void ws_client::on_read(const std::error_code &ec, std::size_t)
    { // read the first two bytes of the message (opcode and length)
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

        std::istream is(&msg->buffer);
        is.read(reinterpret_cast<char *>(&msg->fin_rsv_opcode), 1);

        char len; // second byte of the message
        is.read(&len, 1);
        size_t length = len & 0x7F; // length of the payload
        if (length == 126)
            asio::async_read(socket, msg->buffer, asio::transfer_exactly(2), [this](const std::error_code &, std::size_t)
                             { char buf[2];
                                      std::istream is(&msg->buffer);
                                      is.read(buf, 2);
                                      size_t length = (buf[0] << 8) | buf[1];
                                      asio::async_read(socket, msg->buffer, asio::transfer_exactly(length + 4), std::bind(&ws_client::on_message, this, asio::placeholders::error, asio::placeholders::bytes_transferred)); });
        else if (length == 127)
            asio::async_read(socket, msg->buffer, asio::transfer_exactly(8), [this](const std::error_code &, std::size_t)
                             { char buf[8];
                                      std::istream is(&msg->buffer);
                                      is.read(buf, 8);
                                      size_t length = 0;
                                      for (size_t i = 0; i < 8; i++)
                                          length = (length << 8) | buf[i];
                                      asio::async_read(socket, msg->buffer, asio::transfer_exactly(length + 4), std::bind(&ws_client::on_message, this, asio::placeholders::error, asio::placeholders::bytes_transferred)); });
        else
            asio::async_read(socket, msg->buffer, asio::transfer_exactly(length + 4), std::bind(&ws_client::on_message, this, asio::placeholders::error, asio::placeholders::bytes_transferred));
    }

    void ws_client::on_message(const std::error_code &ec, std::size_t bytes_transferred)
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

        std::istream is(&msg->buffer);
        char mask[4]; // mask for the message
        is.read(mask, 4);
        for (size_t i = 0; i < bytes_transferred - 4; i++) // unmask the message
            *msg->payload += is.get() ^ mask[i % 4];

        if (msg->fin_rsv_opcode & 0x80) // fin bit is set
            on_message_handler(*msg->payload);

        read(); // read the next message
    }
} // namespace network
