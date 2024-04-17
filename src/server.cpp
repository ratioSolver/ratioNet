#include <iostream>
#include "server.hpp"
#include "logging.hpp"

namespace network
{
    session::session(server &srv, boost::asio::ip::tcp::socket socket) : srv(srv), socket(std::move(socket)) {}
    session::~session() {}

    void session::start() { boost::asio::async_read_until(socket, buffer, "\r\n\r\n", std::bind(&session::on_read, shared_from_this(), std::placeholders::_1, std::placeholders::_2)); }

    void session::on_read(const boost::system::error_code &ec, std::size_t bytes_transferred)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        std::istream is(&buffer);

        switch (is.get())
        {
        case 'D':
            if (is.get() == 'E' && is.get() == 'L' && is.get() == 'E' && is.get() == 'T' && is.get() == 'E')
                v = DELETE;
            break;
        case 'G':
            if (is.get() == 'E' && is.get() == 'T')
                v = GET;
            break;
        case 'P':
            switch (is.get())
            {
            case 'O':
                if (is.get() == 'S' && is.get() == 'T')
                    v = POST;
                break;
            case 'U':
                if (is.get() == 'T')
                    v = PUT;
                break;
            }
            break;
        }
        is.get(); // consume space

        while (is.peek() != ' ')
            target += is.get();
        is.get(); // consume space

        while (is.peek() != '\r')
            version += is.get();
        is.get(); // consume '\r'
        is.get(); // consume '\n'

        while (is.peek() != '\r')
        {
            std::string header, value;
            while (is.peek() != ':')
                header += is.get();
            is.get(); // consume ':'
            is.get(); // consume space
            while (is.peek() != '\r')
                value += is.get();
            is.get(); // consume '\r'
            is.get(); // consume '\n'
            headers.emplace(std::move(header), std::move(value));
        }
        is.get(); // consume '\r'
        is.get(); // consume '\n'

        if (headers.find("Upgrade") != headers.end())
        { // handle websocket
            LOG_DEBUG("Websocket not implemented");
            return;
        }

        if (headers.find("Content-Length") != headers.end())
        { // read body
            std::size_t content_length = std::stoul(headers["Content-Length"]);
            boost::asio::async_read(socket, buffer, boost::asio::transfer_exactly(content_length), std::bind(&session::on_body, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
        }
        else
            srv.handle_request(request(shared_from_this(), v, std::move(target), std::move(version), std::move(headers)));
    }

    void session::on_body(const boost::system::error_code &ec, std::size_t bytes_transferred)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        std::istream is(&buffer);
        if (headers.find("Content-Type") != headers.end())
        {
            if (headers["Content-Type"] == "application/json")
                return srv.handle_request(json_request(shared_from_this(), v, std::move(target), std::move(version), std::move(headers), json::load(is)));
            std::string body;
            while (is.peek() != EOF)
                body += is.get();
            return srv.handle_request(string_request(shared_from_this(), v, std::move(target), std::move(version), std::move(headers), std::move(body)));
        }
        srv.handle_request(request(shared_from_this(), v, std::move(target), std::move(version), std::move(headers)));
    }

    server::server(const std::string &address, unsigned short port, std::size_t concurrency_hint) : io_ctx(concurrency_hint), endpoint(boost::asio::ip::make_address(address), port), acceptor(boost::asio::make_strand(io_ctx)) { threads.reserve(concurrency_hint); }
    server::~server() { stop(); }

    void server::start()
    {
        LOG_INFO("Starting server on " + endpoint.address().to_string() + ":" + std::to_string(endpoint.port()));

        boost::system::error_code ec;
        acceptor.open(endpoint.protocol(), ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
        acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
        acceptor.bind(endpoint, ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
        acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        do_accept();

        for (auto i = threads.capacity(); i > 0; --i)
            threads.emplace_back([this]
                                 { io_ctx.run(); });

        io_ctx.run();
    }

    void server::stop()
    {
        LOG_INFO("Stopping server");
        io_ctx.stop();
        for (auto &thread : threads)
            thread.join();
    }

    void server::do_accept() { acceptor.async_accept(io_ctx, std::bind(&server::on_accept, this, std::placeholders::_1, std::placeholders::_2)); }

    void server::on_accept(const boost::system::error_code &ec, boost::asio::ip::tcp::socket socket)
    {
        if (!ec)
            std::make_shared<session>(*this, std::move(socket))->start();

        do_accept();
    }

    void server::handle_request(request &&req)
    {
        std::cout << req << std::endl;
    }
} // namespace network