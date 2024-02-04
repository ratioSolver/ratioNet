#include <boost/beast.hpp>
#include "async_server.hpp"

namespace network::async
{
    void session_detector::run() { boost::asio::dispatch(stream.get_executor(), boost::beast::bind_front_handler(&session_detector::on_run, shared_from_this())); }
    void session_detector::on_run()
    {
        stream.expires_after(std::chrono::seconds(30));                                                                                     // Set the timeout
        boost::beast::async_detect_ssl(stream, buffer, boost::beast::bind_front_handler(&session_detector::on_detect, shared_from_this())); // Detect SSL
    }
    void session_detector::on_detect(boost::beast::error_code ec, bool result)
    {
        if (ec)
            throw std::runtime_error(ec.message());
        else if (result)
            std::make_shared<ssl_session>(srv, std::move(buffer))->run();
        else
            std::make_shared<plain_session>(srv, std::move(buffer))->run();
    }

    server::server(const std::string &address, unsigned short port, std::size_t concurrency_hint) : network::server(address, port, concurrency_hint) {}

    void server::do_accept() { acceptor.async_accept(boost::asio::make_strand(io_ctx), boost::beast::bind_front_handler(&server::on_accept, this)); }

    void server::on_accept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket)
    {
        if (ec)
            throw std::runtime_error(ec.message());
        else
            std::make_shared<session_detector>(*this, std::move(socket))->run();
        do_accept(); // Accept another connection
    }
} // namespace network