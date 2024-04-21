#include "client.hpp"
#include "logging.hpp"

namespace network
{
    client::client(const std::string &host, unsigned short port) : host(host), port(port), resolver(io_ctx), socket(io_ctx), strand(boost::asio::make_strand(io_ctx)) { connect(); }

    void client::enqueue(std::unique_ptr<request> req)
    {
        boost::asio::post(strand, [this, r = std::move(req)]() mutable
                          { req_queue.push(std::move(r));
                            if (!socket.is_open())
                                connect();
                            else if (req_queue.size() == 1)
                                write(); });
    }

    void client::connect() { resolver.async_resolve(host, std::to_string(port), std::bind(&client::on_resolve, this, std::placeholders::_1, std::placeholders::_2)); }

    void client::write()
    {
        LOG_DEBUG(*req_queue.front());
        boost::asio::async_write(socket, req_queue.front()->get_buffer(), std::bind(&client::on_write, this, std::placeholders::_1, std::placeholders::_2));
    }

    void client::on_resolve(const boost::system::error_code &ec, boost::asio::ip::tcp::resolver::results_type results)
    {
        if (ec)
        {
            LOG_ERR("Failed to resolve host: " + ec.message());
            return;
        }

        boost::asio::async_connect(socket, results, std::bind(&client::on_connect, this, std::placeholders::_1));
    }

    void client::on_connect(const boost::system::error_code &ec)
    {
        if (ec)
        {
            LOG_ERR("Failed to connect to host: " + ec.message());
            return;
        }

        LOG_INFO("Connected to host");
        if (!req_queue.empty())
            write();
    }

    void client::on_write(const boost::system::error_code &ec, std::size_t bytes_transferred)
    {
        if (ec)
        {
            LOG_ERR("Failed to write to host: " + ec.message());
            return;
        }

        req_queue.pop();
        if (!req_queue.empty())
            write();
    }

    void client::on_read(const boost::system::error_code &ec, std::size_t bytes_transferred)
    {
        if (ec == boost::asio::error::eof)
            return; // connection closed by server
        else if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
    }
} // namespace network