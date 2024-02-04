#include "sync_server.hpp"

namespace network::sync
{
    void session_detector::run()
    {
        boost::beast::error_code ec;
        stream.expires_after(std::chrono::seconds(30));
        bool result = boost::beast::detect_ssl(stream, buffer, ec);
        if (ec)
            throw std::runtime_error(ec.message());
        else if (result)
            std::make_shared<ssl_session>(srv, std::move(buffer))->run();
        else
            std::make_shared<plain_session>(srv, std::move(buffer))->run();
    }

    server::server(const std::string &address, unsigned short port, std::size_t concurrency_hint) : network::server(address, port, concurrency_hint) {}

    void server::do_accept()
    {
        while (true)
        {
            boost::asio::ip::tcp::socket socket(io_ctx);
            acceptor.accept(socket);
            std::make_shared<session_detector>(*this, std::move(socket))->run();
        }
    }
} // namespace network