#include "sync_server.hpp"

namespace network::sync
{
    server::server(const std::string &address, unsigned short port, std::size_t concurrency_hint) : network::server(address, port, concurrency_hint) {}

    void server::do_accept()
    {
        while (true)
        { // Accept a new connection
            boost::asio::ip::tcp::socket socket(io_ctx);
            acceptor.accept(socket);
            session_detector(*this, std::move(socket)).run();
        }
    }

    void session_detector::run()
    {
        boost::beast::error_code ec;
        stream.expires_after(std::chrono::seconds(30));
        bool result = boost::beast::detect_ssl(stream, buffer, ec);
        if (ec)
            throw std::runtime_error(ec.message());
        else if (result)
            static_cast<server &>(srv).sessions.emplace(std::make_unique<ssl_session>(srv, std::move(buffer))).first->get()->run();
        else
            static_cast<server &>(srv).sessions.emplace(std::make_unique<plain_session>(srv, std::move(buffer))).first->get()->run();
    }
} // namespace network