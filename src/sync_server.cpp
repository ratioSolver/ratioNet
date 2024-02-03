#include "sync_server.hpp"

namespace network::sync
{
    void session_detector::run()
    {
        boost::beast::error_code ec;
        stream.expires_after(std::chrono::seconds(30));
        if (boost::beast::detect_ssl(stream, buffer, ec))
        {
            // TODO: Handle session detection
        }
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