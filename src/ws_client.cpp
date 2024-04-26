#include "ws_client.hpp"
#include "logging.hpp"

namespace network
{
    ws_client::ws_client(const std::string &host, unsigned short port) : host(host), port(port), resolver(io_ctx), socket(io_ctx), strand(boost::asio::make_strand(io_ctx)) { connect(); }

    void ws_client::enqueue(std::unique_ptr<message> msg)
    {
        boost::asio::post(strand, [this, m = std::move(msg)]() mutable
                          { res_queue.push(std::move(m));
                            if (!socket.is_open())
                                connect();
                            else if (res_queue.size() == 1)
                                write(); });
    }

    void ws_client::connect()
    {
        LOG_DEBUG("Connecting to host " + host + ":" + std::to_string(port));
        resolver.async_resolve(host, std::to_string(port), std::bind(&ws_client::on_resolve, this, std::placeholders::_1, std::placeholders::_2));
    }

    void ws_client::write()
    {
    }

    void ws_client::on_resolve(const boost::system::error_code &ec, boost::asio::ip::tcp::resolver::results_type results)
    {
        if (ec)
        {
            LOG_ERR("Failed to resolve host: " + ec.message());
            return;
        }

        boost::asio::async_connect(socket, results, std::bind(&ws_client::on_connect, this, std::placeholders::_1));
    }

    void ws_client::on_connect(const boost::system::error_code &ec)
    {
    }

    void ws_client::on_write(const boost::system::error_code &ec, std::size_t bytes_transferred)
    {
    }

    void ws_client::on_read(const boost::system::error_code &ec, std::size_t bytes_transferred)
    {
    }
} // namespace network
