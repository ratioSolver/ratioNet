#include "ssl_client.h"

namespace network
{
    ssl_client::ssl_client(const std::string &h, const std::string &srv) : host(h), io_context(), signals(io_context), ssl_context(boost::asio::ssl::context::tlsv12_client), socket(io_context, ssl_context), results(boost::asio::ip::tcp::resolver(io_context).resolve(h, srv))
    {
        signals.add(SIGINT);
        signals.add(SIGTERM);
#if defined(SIGQUIT)
        signals.add(SIGQUIT);
#endif
        signals.async_wait([this](boost::system::error_code, int)
                           { stop(); });

        if (!SSL_set_tlsext_host_name(socket.native_handle(), host.c_str()))
        {
            boost::system::error_code ec{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()};
            throw boost::system::system_error{ec};
        }
    }

    response ssl_client::get(const std::string &target, const std::unordered_map<std::string, std::string> &headers)
    {
        if (!socket.next_layer().is_open())
        {
            boost::asio::connect(socket.next_layer(), results.begin(), results.end());
            socket.handshake(boost::asio::ssl::stream_base::client);
        }
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

    response ssl_client::post(const std::string &target, const std::string &body, const std::unordered_map<std::string, std::string> &headers)
    {
        if (!socket.next_layer().is_open())
        {
            boost::asio::connect(socket.next_layer(), results.begin(), results.end());
            socket.handshake(boost::asio::ssl::stream_base::client);
        }
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

    response ssl_client::put(const std::string &target, const std::string &body, const std::unordered_map<std::string, std::string> &headers)
    {
        if (!socket.next_layer().is_open())
        {
            boost::asio::connect(socket.next_layer(), results.begin(), results.end());
            socket.handshake(boost::asio::ssl::stream_base::client);
        }
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

    response ssl_client::del(const std::string &target, const std::unordered_map<std::string, std::string> &headers)
    {
        if (!socket.next_layer().is_open())
        {
            boost::asio::connect(socket.next_layer(), results.begin(), results.end());
            socket.handshake(boost::asio::ssl::stream_base::client);
        }
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

    void ssl_client::stop()
    {
        socket.next_layer().close();
        io_context.stop();
    }
} // namespace network
