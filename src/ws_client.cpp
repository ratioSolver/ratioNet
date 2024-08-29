#include "ws_client.hpp"
#include "logging.hpp"

namespace network
{
    ws_client::ws_client(const std::string &host, unsigned short port) : host(host), port(port), resolver(io_ctx), socket(io_ctx), strand(asio::make_strand(io_ctx)) { connect(); }

    void ws_client::enqueue(std::unique_ptr<message> msg)
    {
        asio::post(strand, [this, m = std::move(msg)]() mutable
                   { res_queue.push(std::move(m));
                            if (!socket.is_open())
                                connect();
                            else if (res_queue.size() == 1)
                                write(); });
    }

    void ws_client::connect()
    {
        LOG_DEBUG("Connecting to host " + host + ":" + std::to_string(port));
        resolver.async_resolve(host, std::to_string(port), std::bind(&ws_client::on_resolve, this, asio::placeholders::error, asio::placeholders::results));
    }

    void ws_client::write()
    {
    }

    void ws_client::on_resolve(const std::error_code &ec, asio::ip::tcp::resolver::results_type results)
    {
        if (ec)
        {
            LOG_ERR("Failed to resolve host: " + ec.message());
            return;
        }

        asio::async_connect(socket, results, std::bind(&ws_client::on_connect, this, asio::placeholders::error));
    }

    void ws_client::on_connect(const std::error_code &ec)
    {
    }

    void ws_client::on_write(const std::error_code &ec, std::size_t bytes_transferred)
    {
    }

    void ws_client::on_read(const std::error_code &ec, std::size_t bytes_transferred)
    {
    }
} // namespace network
