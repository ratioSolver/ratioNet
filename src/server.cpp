#include <iostream>
#include "server.hpp"

namespace network
{
    session::session(boost::asio::ip::tcp::socket socket) : socket(std::move(socket)) {}
    session::~session() {}

    void session::start() { boost::asio::async_read_until(socket, buffer, '\n', std::bind(&session::on_read, shared_from_this(), std::placeholders::_1, std::placeholders::_2)); }

    void session::on_read(const boost::system::error_code &ec, std::size_t bytes_transferred)
    {
        if (ec)
        {
            std::cerr << ec.message() << std::endl;
            return;
        }

        std::istream is(&buffer);
        std::string line;
        std::getline(is, line);
    }

    server::server(const std::string &address, unsigned short port, std::size_t concurrency_hint) : io_ctx(concurrency_hint), endpoint(boost::asio::ip::make_address(address), port), acceptor(boost::asio::make_strand(io_ctx)) { threads.reserve(concurrency_hint); }

    void server::start()
    {
        std::cout << "Starting server on " << endpoint << std::endl;

        boost::system::error_code ec;
        acceptor.open(endpoint.protocol(), ec);
        if (ec)
        {
            std::cerr << ec.message() << std::endl;
            return;
        }
        acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec);
        if (ec)
        {
            std::cerr << ec.message() << std::endl;
            return;
        }
        acceptor.bind(endpoint, ec);
        if (ec)
        {
            std::cerr << ec.message() << std::endl;
            return;
        }
        acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
        if (ec)
        {
            std::cerr << ec.message() << std::endl;
            return;
        }

        do_accept();

        for (auto i = threads.capacity(); i > 0; --i)
            threads.emplace_back([this]
                                 { io_ctx.run(); });

        io_ctx.run();
    }

    void server::do_accept() { acceptor.async_accept(io_ctx, std::bind(&server::on_accept, this, std::placeholders::_1, std::placeholders::_2)); }

    void server::on_accept(const boost::system::error_code &ec, boost::asio::ip::tcp::socket socket)
    {
        if (!ec)
            std::make_shared<session>(std::move(socket))->start();

        do_accept();
    }
} // namespace network