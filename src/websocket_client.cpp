#include "websocket_client.h"

namespace network
{
    websocket_client::websocket_client(const std::string &h, const std::string &srv, const std::string &path) : host(h), path(path), signals(io_context), resolver(io_context), ws(io_context)
    {
        signals.add(SIGINT);
        signals.add(SIGTERM);
#if defined(SIGQUIT)
        signals.add(SIGQUIT);
#endif
        signals.async_wait([this](boost::system::error_code, int)
                           { close(); });

        resolver.async_resolve(host, srv, std::bind(&websocket_client::on_resolve, this, std::placeholders::_1, std::placeholders::_2));
    }

    void websocket_client::start() { io_context.run(); }

    void websocket_client::send(message_ptr msg)
    {
        // post to strand to avoid concurrent write..
        boost::asio::post(ws.get_executor(), [this, msg]()
                          { on_send(msg); });
    }

    void websocket_client::close(boost::beast::websocket::close_code code)
    {
        ws.async_close(code, [this](boost::system::error_code ec)
                       { on_close(ec); });
    }

    void websocket_client::on_resolve(boost::system::error_code ec, boost::asio::ip::tcp::resolver::results_type results)
    {
        if (ec)
        {
            on_error_handler(ec);
            return;
        }

        boost::beast::get_lowest_layer(ws).expires_after(std::chrono::seconds(30));
        boost::beast::get_lowest_layer(ws).async_connect(results, std::bind(&websocket_client::on_connect, this, std::placeholders::_1, std::placeholders::_2));
    }

    void websocket_client::on_connect(boost::system::error_code ec, boost::asio::ip::tcp::resolver::results_type::endpoint_type)
    {
        if (ec)
        {
            on_error_handler(ec);
            return;
        }

        boost::beast::get_lowest_layer(ws).expires_never();
        ws.set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::client));
        ws.set_option(boost::beast::websocket::stream_base::decorator([](boost::beast::websocket::request_type &req)
                                                                      { req.set(boost::beast::http::field::user_agent, std::string(BOOST_BEAST_VERSION_STRING) + " websocket-client-async"); }));
        ws.async_handshake(host, path, std::bind(&websocket_client::on_handshake, this, std::placeholders::_1));
    }

    void websocket_client::on_handshake(boost::system::error_code ec)
    {
        if (ec)
        {
            on_error_handler(ec);
            return;
        }

        on_open_handler();

        ws.async_read(buffer, std::bind(&websocket_client::on_read, this, std::placeholders::_1, std::placeholders::_2));
    }

    void websocket_client::on_send(message_ptr msg)
    {
        send_queue.push(msg);

        if (send_queue.size() > 1)
            return;

        ws.async_write(boost::asio::buffer(send_queue.front()->get()), std::bind(&websocket_client::on_write, this, std::placeholders::_1, std::placeholders::_2));
    }

    void websocket_client::on_write(boost::system::error_code ec, std::size_t)
    {
        if (ec)
        {
            on_error_handler(ec);
            return;
        }
    }

    void websocket_client::on_read(boost::system::error_code ec, std::size_t)
    {
        if (ec)
        {
            on_error_handler(ec);
            return;
        }

        on_message_handler(boost::beast::buffers_to_string(buffer.data()));

        ws.async_read(buffer, std::bind(&websocket_client::on_read, this, std::placeholders::_1, std::placeholders::_2));
    }

    void websocket_client::on_close(boost::system::error_code ec)
    {
        if (ec)
        {
            on_error_handler(ec);
            return;
        }

        on_close_handler();

        io_context.stop();
    }
} // namespace network
