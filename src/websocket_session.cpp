#include "websocket_session.h"
#include "server.h"

namespace network
{
    websocket_session::websocket_session(server &srv, boost::asio::ip::tcp::socket &&socket, ws_handlers &handlers) : srv(srv), ws(std::move(socket)), handlers(handlers) {}
    websocket_session::~websocket_session() { srv.sessions.erase(this); }

    void websocket_session::send(message_ptr msg)
    {
        // post to strand to avoid concurrent write..
        boost::asio::post(ws.get_executor(), [this, msg]()
                          { on_send(msg); });
    }

    void websocket_session::close(boost::beast::websocket::close_code code)
    {
        ws.async_close(code, [this](boost::system::error_code ec)
                       { on_close(ec); });
    }

    void websocket_session::run(boost::beast::http::request<boost::beast::http::dynamic_body> req)
    {
        ws.async_accept(req, [this](boost::system::error_code ec)
                        { on_accept(ec); });
    }

    void websocket_session::on_send(message_ptr msg)
    {
        send_queue.push(msg);

        if (send_queue.size() > 1)
            return;

        ws.async_write(boost::asio::buffer(send_queue.front()->get()), [this](boost::system::error_code ec, std::size_t bytes_transferred)
                       { on_write(ec, bytes_transferred); });
    }

    void websocket_session::on_accept(boost::system::error_code ec)
    {
        if (ec)
        {
            handlers.on_error_handler(*this, ec);
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
        if (ec)
        {
            handlers.on_error_handler(*this, ec);
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
        if (ec)
        {
            handlers.on_error_handler(*this, ec);
            delete this;
            return;
        }

        send_queue.pop();

        if (!send_queue.empty())
            ws.async_write(boost::asio::buffer(send_queue.front()->get()), [this](boost::system::error_code ec, std::size_t bytes_transferred)
                           { on_write(ec, bytes_transferred); });
    }

    void websocket_session::on_close(boost::system::error_code ec)
    {
        if (ec)
        {
            handlers.on_error_handler(*this, ec);
            delete this;
            return;
        }

        handlers.on_close_handler(*this);
        delete this;
    }
} // namespace network