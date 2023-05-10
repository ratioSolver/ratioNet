#include "websocket_session.h"
#include "server.h"
#include "logging.h"

namespace network
{
    websocket_session::websocket_session(server &srv, boost::asio::ip::tcp::socket &&socket, ws_handlers &handlers) : srv(srv), ws(std::move(socket)), handlers(handlers) { LOG("WebSocket session created.."); }
    websocket_session::~websocket_session()
    {
        LOG("WebSocket session destroyed..");
        srv.sessions.erase(this);
    }

    void websocket_session::run(boost::beast::http::request<boost::beast::http::string_body> req)
    {
        LOG("Running WebSocket session..");
        ws.async_accept(req, [this](boost::system::error_code ec)
                        { on_accept(ec); });
    }

    void websocket_session::send(utils::c_ptr<message> msg)
    {
        LOG("Sending: " << msg->msg);
        send_queue.push(msg);

        if (send_queue.size() > 1)
            return;

        ws.async_write(boost::asio::buffer(send_queue.front()->msg), [this](boost::system::error_code ec, std::size_t bytes_transferred)
                       { on_write(ec, bytes_transferred); });
    }

    void websocket_session::on_accept(boost::system::error_code ec)
    {
        LOG("WebSocket session accepted..");
        if (ec)
        {
            LOG_ERR("Error on accept: " << ec.message());
            handlers.on_close_handler(*this);
            delete this;
            return;
        }

        srv.sessions.insert(this);

        handlers.on_open_handler(*this);

        // read message..
        ws.async_read(buffer, [this](boost::system::error_code ec, std::size_t bytes_transferred)
                      { on_read(ec, bytes_transferred); });
    }

    void websocket_session::on_read(boost::system::error_code ec, std::size_t)
    {
        LOG("Data received..");
        if (ec)
        {
            LOG_ERR("Error on read: " << ec.message());
            handlers.on_close_handler(*this);
            delete this;
            return;
        }

        handlers.on_message_handler(*this, boost::beast::buffers_to_string(buffer.data()));
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
            handlers.on_close_handler(*this);
            delete this;
            return;
        }

        send_queue.pop();

        if (!send_queue.empty())
            ws.async_write(boost::asio::buffer(send_queue.front()->msg), [this](boost::system::error_code ec, std::size_t bytes_transferred)
                           { on_write(ec, bytes_transferred); });
    }
} // namespace network