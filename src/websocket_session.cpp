#include "websocket_session.h"
#include "logging.h"

namespace network
{
    websocket_session::websocket_session(boost::asio::ip::tcp::socket &&socket) : ws(std::move(socket)) {}

    void websocket_session::run(boost::beast::http::request<boost::beast::http::string_body> req)
    {
        LOG("Running WebSocket session..");
        ws.async_accept(req, [this](boost::system::error_code ec)
                        { on_accept(ec); });
    }

    void websocket_session::send(const std::string &&message)
    {
        LOG("Sending: " << message);
        send_queue.push(utils::u_ptr<std::string>(new std::string(message)));

        if (send_queue.size() > 1)
            return;

        ws.async_write(boost::asio::buffer(*send_queue.front()), [this](boost::system::error_code ec, std::size_t bytes_transferred)
                       { on_write(ec, bytes_transferred); });
    }

    void websocket_session::on_accept(boost::system::error_code ec)
    {
        LOG("WebSocket session accepted..");
        if (ec)
        {
            LOG_ERR("Error on accept: " << ec.message());
            delete this;
            return;
        }

        ws.async_read(buffer, [this](boost::system::error_code ec, std::size_t bytes_transferred)
                      { on_read(ec, bytes_transferred); });
    }

    void websocket_session::on_read(boost::system::error_code ec, std::size_t)
    {
        LOG("Data received..");
        if (ec)
        {
            LOG_ERR("Error on read: " << ec.message());
            delete this;
            return;
        }

        // TODO: handle message
        LOG("Received: " << boost::beast::buffers_to_string(buffer.data()));

        buffer.consume(buffer.size());

        // read another message..
        ws.async_read(buffer, [this](boost::system::error_code ec, std::size_t bytes_transferred)
                      { on_read(ec, bytes_transferred); });
    }

    void websocket_session::on_write(boost::system::error_code ec, std::size_t)
    {
        LOG("Data sent..");
        if (ec)
        {
            LOG_ERR("Error on write: " << ec.message());
            delete this;
            return;
        }

        send_queue.pop();

        if (!send_queue.empty())
            ws.async_write(boost::asio::buffer(*send_queue.front()), [this](boost::system::error_code ec, std::size_t bytes_transferred)
                           { on_write(ec, bytes_transferred); });
    }
} // namespace network