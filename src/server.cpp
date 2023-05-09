#include "server.h"
#include "logging.h"

namespace network
{
    server::server(std::string address, unsigned short port) : ctx(), acceptor(ctx, boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address(address), port)), socket(ctx) {}

    void server::run()
    {
        LOG("Server listening on " << acceptor.local_endpoint() << "..");
        do_accept();
        ctx.run();
    }

    void server::do_accept()
    {
        acceptor.async_accept(socket, [this](boost::system::error_code ec)
                              {
            if (!ec)
            {
                // Receive and handle incoming HTTP requests and WebSocket requests..
                boost::beast::flat_buffer buffer;
                boost::beast::http::request_parser<boost::beast::http::string_body> parser;
                boost::beast::http::read_header(socket, buffer, parser); // Read the header of the HTTP request..
                if (parser.get().find(boost::beast::http::field::upgrade) != parser.get().end() && boost::beast::iequals(parser.get()[boost::beast::http::field::upgrade], "websocket"))
                {
                    boost::beast::websocket::stream<boost::beast::tcp_stream> websocket(std::move(socket));
                    websocket.accept(parser.get());
                    handle_websocket_request(parser.get(), websocket);
                }
                else
                {
                    boost::beast::http::read(socket, buffer, parser); // Read the body of the HTTP request..
                    boost::beast::http::response<boost::beast::http::string_body> response;
                    response.version(parser.get().version());
                    response.keep_alive(parser.get().keep_alive());
                    handle_http_request(parser.get(), response);
                    boost::beast::http::write(socket, response);
                    socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send);
                    socket.close();
                }
            }
            else
                LOG_ERR("Error accepting HTTP request: " << ec.message());
            do_accept(); });
    }

    void server::add_route(boost::beast::http::verb method, std::string regex, std::function<void(boost::beast::http::request<boost::beast::http::string_body> &, boost::beast::http::response<boost::beast::http::string_body> &)> callback)
    {
        switch (method)
        {
        case boost::beast::http::verb::get:
            get_routes.push_back(std::make_pair(std::regex(regex), callback));
            break;
        case boost::beast::http::verb::post:
            post_routes.push_back(std::make_pair(std::regex(regex), callback));
            break;
        case boost::beast::http::verb::put:
            put_routes.push_back(std::make_pair(std::regex(regex), callback));
            break;
        case boost::beast::http::verb::delete_:
            delete_routes.push_back(std::make_pair(std::regex(regex), callback));
            break;
        default:
            LOG_ERR("Invalid request method");
            break;
        }
    }

    void server::add_websocket_route(std::string regex, std::function<void(boost::beast::http::request<boost::beast::http::string_body> &, boost::beast::websocket::stream<boost::beast::tcp_stream> &)> callback) { websocket_routes.push_back(std::make_pair(std::regex(regex), callback)); }

    void server::handle_http_request(boost::beast::http::request<boost::beast::http::string_body> &request, boost::beast::http::response<boost::beast::http::string_body> &response)
    {
        switch (request.method())
        {
        case boost::beast::http::verb::get:
            for (auto &route : get_routes)
                if (std::regex_match(request.target().to_string(), route.first))
                {
                    route.second(request, response);
                    return;
                }
            break;
        case boost::beast::http::verb::post:
            for (auto &route : post_routes)
                if (std::regex_match(request.target().to_string(), route.first))
                {
                    route.second(request, response);
                    return;
                }
            break;
        case boost::beast::http::verb::put:
            for (auto &route : put_routes)
                if (std::regex_match(request.target().to_string(), route.first))
                {
                    route.second(request, response);
                    return;
                }
            break;
        case boost::beast::http::verb::delete_:
            for (auto &route : delete_routes)
                if (std::regex_match(request.target().to_string(), route.first))
                {
                    route.second(request, response);
                    return;
                }
            break;
        default:
            LOG_ERR("Invalid request method");
            break;
        }
        LOG_WARN("Invalid HTTP request: " << request.target().to_string());
        response.result(boost::beast::http::status::not_found);
        response.set(boost::beast::http::field::content_type, "text/html");
        response.body() = "404 Not Found";
    }

    void server::handle_websocket_request(boost::beast::http::request<boost::beast::http::string_body> &request, boost::beast::websocket::stream<boost::beast::tcp_stream> &websocket)
    {
        for (auto &route : websocket_routes)
            if (std::regex_match(request.target().to_string(), route.first))
            {
                route.second(request, websocket);
                return;
            }

        LOG_WARN("Invalid websocket request: " << request.target().to_string());
    }
} // namespace network