#include "client.h"
#include <boost/beast/ssl.hpp>

namespace network
{
    client::client(const std::string &h, const std::string &srv) : host(h), signals(io_context), socket(io_context), results(boost::asio::ip::tcp::resolver(io_context).resolve(h, srv))
    {
        signals.add(SIGINT);
        signals.add(SIGTERM);
#if defined(SIGQUIT)
        signals.add(SIGQUIT);
#endif
        signals.async_wait([this](boost::system::error_code, int)
                           { stop(); });
    }

    response client::get(const std::string &target, const std::unordered_map<std::string, std::string> &headers)
    {
        if (!socket.is_open()){
            boost::asio::connect(socket, results.begin(), results.end());}
        boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::get, target, 11};
        req.set(boost::beast::http::field::host, host);
        for (const auto &[key, value] : headers)
            req.set(key, value);
        boost::beast::http::write(socket, req);
        boost::beast::flat_buffer buffer;
        boost::beast::http::response<boost::beast::http::dynamic_body> res;
        boost::beast::http::read(socket, buffer, res);
        return res;
    }

    response client::post(const std::string &target, const std::string &body, const std::unordered_map<std::string, std::string> &headers)
    {
        if (!socket.is_open())
            boost::asio::connect(socket, results.begin(), results.end());
        boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::post, target, 11};
        req.set(boost::beast::http::field::host, host);
        req.set(boost::beast::http::field::content_type, "application/json");
        req.body() = body;
        req.prepare_payload();
        for (const auto &[key, value] : headers)
            req.set(key, value);
        boost::beast::http::write(socket, req);
        boost::beast::flat_buffer buffer;
        boost::beast::http::response<boost::beast::http::dynamic_body> res;
        boost::beast::http::read(socket, buffer, res);
        return res;
    }

    response client::put(const std::string &target, const std::string &body, const std::unordered_map<std::string, std::string> &headers)
    {
        if (!socket.is_open())
            boost::asio::connect(socket, results.begin(), results.end());
        boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::put, target, 11};
        req.set(boost::beast::http::field::host, host);
        req.set(boost::beast::http::field::content_type, "application/json");
        req.body() = body;
        req.prepare_payload();
        for (const auto &[key, value] : headers)
            req.set(key, value);
        boost::beast::http::write(socket, req);
        boost::beast::flat_buffer buffer;
        boost::beast::http::response<boost::beast::http::dynamic_body> res;
        boost::beast::http::read(socket, buffer, res);
        return res;
    }

    response client::del(const std::string &target, const std::unordered_map<std::string, std::string> &headers)
    {
        if (!socket.is_open())
            boost::asio::connect(socket, results.begin(), results.end());
        boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::delete_, target, 11};
        req.set(boost::beast::http::field::host, host);
        for (const auto &[key, value] : headers)
            req.set(key, value);
        boost::beast::http::write(socket, req);
        boost::beast::flat_buffer buffer;
        boost::beast::http::response<boost::beast::http::dynamic_body> res;
        boost::beast::http::read(socket, buffer, res);
        return res;
    }

    void client::stop()
    {
        if (socket.is_open())
            socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
        io_context.stop();
    }
} // namespace network
