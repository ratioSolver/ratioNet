#include "ws_client.hpp"
#include "base64.hpp"
#include "request.hpp"
#include "response.hpp"
#include "logging.hpp"

namespace network
{
#ifdef ENABLE_SSL
    ws_client::ws_client(std::string_view host, unsigned short port, std::string_view trgt) : host(host), port(port), target(trgt), resolver(io_ctx), socket(io_ctx, ssl_ctx) {}
#else
    ws_client::ws_client(std::string_view host, unsigned short port, std::string_view trgt) : host(host), port(port), target(trgt), resolver(io_ctx), socket(io_ctx) {}
#endif
    ws_client::~ws_client() { LOG_TRACE("WebSocket client destroyed"); }

    void ws_client::enqueue(utils::u_ptr<message> res)
    {
        asio::post(socket.get_executor(), [this, r = std::move(res)]() mutable
                   { res_queue.push(std::move(r));
                            if (res_queue.size() == 1)
                                write(); });
    }

    void ws_client::disconnect()
    {
        LOG_DEBUG("Disconnecting from " << host << ":" << port << "...");
        std::error_code ec;
#ifdef ENABLE_SSL
        socket.lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
#else
        socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
#endif
        if (ec == asio::error::eof)
        { // connection closed by server
            ec.clear();
            LOG_DEBUG("Connection closed by server");
        }
        else if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
#ifdef ENABLE_SSL
        socket.lowest_layer().close(ec);
#else
        socket.close(ec);
#endif
        if (ec)
            LOG_ERR(ec.message());
        LOG_DEBUG("Disconnected from " << host << ":" << port);
    }

    void ws_client::connect()
    {
        LOG_DEBUG("Connecting to " << host << ":" << port << "...");
        std::error_code ec;
#ifdef ENABLE_SSL
        asio::connect(socket.lowest_layer(), resolver.resolve(host, std::to_string(port)), ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
        socket.set_verify_mode(asio::ssl::verify_peer);
        socket.set_verify_callback(asio::ssl::host_name_verification(host));
        socket.handshake(asio::ssl::stream_base::client, ec);
#else
        asio::connect(socket, resolver.resolve(host, std::to_string(port)), ec);
#endif
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
        LOG_DEBUG("Connected to " << host << ":" << port);

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
        auto req = utils::make_u_ptr<request>(verb::Get, std::string(target), "HTTP/1.1", std::move(hdrs));
        asio::write(socket, req->get_buffer(), ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        auto res = utils::make_u_ptr<response>();
        asio::read_until(socket, res->buffer, "\r\n\r\n", ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        res->parse();

        if (res->get_status_code() != status_code::websocket_switching_protocols)
        {
            LOG_ERR("WebSocket handshake failed");
            return;
        }

        on_open_handler();
        read(); // read the first message

        io_ctx.run();
    }

    void ws_client::read()
    {
        msg = utils::make_u_ptr<message>();
        asio::async_read(socket, msg->buffer, asio::transfer_exactly(2), std::bind(&ws_client::on_read, this, asio::placeholders::error, asio::placeholders::bytes_transferred));
    }

    void ws_client::write() { asio::async_write(socket, res_queue.front()->get_buffer(), std::bind(&ws_client::on_write, this, asio::placeholders::error, asio::placeholders::bytes_transferred)); }

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
                                      asio::async_read(socket, msg->buffer, asio::transfer_exactly(length), std::bind(&ws_client::on_message, this, asio::placeholders::error, asio::placeholders::bytes_transferred)); });
        else if (length == 127)
            asio::async_read(socket, msg->buffer, asio::transfer_exactly(8), [this](const std::error_code &, std::size_t)
                             { char buf[8];
                                      std::istream is(&msg->buffer);
                                      is.read(buf, 8);
                                      size_t length = 0;
                                      for (size_t i = 0; i < 8; i++)
                                          length = (length << 8) | buf[i];
                                      asio::async_read(socket, msg->buffer, asio::transfer_exactly(length), std::bind(&ws_client::on_message, this, asio::placeholders::error, asio::placeholders::bytes_transferred)); });
        else
            asio::async_read(socket, msg->buffer, asio::transfer_exactly(length), std::bind(&ws_client::on_message, this, asio::placeholders::error, asio::placeholders::bytes_transferred));
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
        for (size_t i = 0; i < bytes_transferred; i++)
            *msg->payload += is.get();

        if (msg->fin_rsv_opcode & 0x80) // fin bit is set
            on_message_handler(*msg->payload);

        read(); // read the next message
    }

    void ws_client::on_write(const std::error_code &ec, std::size_t)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            while (!res_queue.empty()) // clear the response queue
                res_queue.pop();
            on_error_handler(ec);
            return;
        }

        res_queue.pop();
        if (!res_queue.empty())
            write(); // write the next message
    }
} // namespace network
