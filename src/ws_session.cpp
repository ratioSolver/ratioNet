#include "ws_session.hpp"
#include "server.hpp"
#include "logging.hpp"

namespace network
{
    ws_session::ws_session(server &srv, boost::asio::ip::tcp::socket &&socket) : srv(srv), socket(std::move(socket)) { LOG_TRACE("WebSocket session created with " << this->socket.remote_endpoint()); }
    ws_session::~ws_session() { LOG_TRACE("WebSocket session destroyed"); }

    void ws_session::read()
    {
    }

    void ws_session::enqueue(std::unique_ptr<std::string> res)
    {
        boost::asio::post(socket.get_executor(), [self = shared_from_this(), r = std::move(res)]() mutable
                          { self->res_queue.push(std::move(r));
                            if (self->res_queue.size() == 1)
                                self->write(); });
    }

    void ws_session::write()
    {
        boost::asio::async_write(socket, boost::asio::buffer(*res_queue.front()), std::bind(&ws_session::on_write, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
    }

    void ws_session::on_read(const boost::system::error_code &ec, std::size_t bytes_transferred)
    {
        if (ec == boost::asio::error::eof)
            return; // connection closed by client
        else if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
    }

    void ws_session::on_write(const boost::system::error_code &ec, std::size_t bytes_transferred)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        res_queue.pop();
        if (!res_queue.empty())
            write();
    }
} // namespace network