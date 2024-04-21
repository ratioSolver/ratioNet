#include "client.hpp"
#include "logging.hpp"

namespace network
{
    client::client(const std::string &host, unsigned short port) : host(host), port(port), resolver(io_ctx), socket(io_ctx) { connect(); }

    void client::connect() { resolver.async_resolve(host, std::to_string(port), std::bind(&client::on_resolve, this, std::placeholders::_1, std::placeholders::_2)); }

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
    }
} // namespace network