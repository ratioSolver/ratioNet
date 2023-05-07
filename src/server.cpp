#include "server.h"
#include <iostream>

namespace network
{
    server::server(short port) : io_service(), acceptor(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)), socket(io_service)
    {
        start_accept();
        io_service.run();
    }

    void server::start_accept()
    {
        acceptor.async_accept(socket, [this](boost::system::error_code ec)
                              {
            if (!ec)
            {
                request req = parse_request(socket);
                std::function<response_ptr(request &)> *cb = nullptr;
                switch (req.m)
                {
                case method::GET:
                    if (get_routes.find(req.path) != get_routes.end())
                        cb = &get_routes[req.path];
                    break;
                case method::POST:
                    if (post_routes.find(req.path) != post_routes.end())
                        cb = &post_routes[req.path];
                    break;
                case method::PUT:
                    if (put_routes.find(req.path) != put_routes.end())
                        cb = &put_routes[req.path];
                    break;
                case method::DELETE:
                    if (delete_routes.find(req.path) != delete_routes.end())
                        cb = &delete_routes[req.path];
                    break;
                }
                if (cb != nullptr)
                {
                    auto res = (*cb)(req);
                    boost::asio::streambuf res_buff;
                    std::ostream output(&res_buff);

                    if (auto json_res = dynamic_cast<json_response *>(res.operator->()))
                        output << json_res;
                    else
                        output << res;
                } else {
                    response res(socket, "HTTP/1.1", 404);
                    boost::asio::streambuf res_buff;
                    std::ostream output(&res_buff);
                    output << res;
                }

                socket.close();
            }

            start_accept(); });
    }

    request server::parse_request(boost::asio::ip::tcp::socket &socket)
    {
        boost::asio::streambuf req_buff;
        std::istream input(&req_buff);
        boost::asio::read_until(socket, req_buff, "\r\n\r\n");
        method method;
        std::string method_str, path, version;
        input >> method_str >> path >> version;
        if (method_str == "GET")
            method = method::GET;
        else if (method_str == "POST")
            method = method::POST;
        else if (method_str == "PUT")
            method = method::PUT;
        else if (method_str == "DELETE")
            method = method::DELETE;

        std::vector<std::string> url_params;
        auto param = path.find("/");
        while (param != std::string::npos)
        {
            auto next_param = path.find("/", param + 1);
            if (next_param != std::string::npos)
            {
                auto name = path.substr(param + 1, next_param - param - 1);
                url_params.push_back(name);
            }
            param = next_param;
        }

        std::map<std::string, std::string> query_params;
        auto query = path.find("?");
        if (query != std::string::npos)
        {
            auto params = path.substr(query + 1);
            path = path.substr(0, query);
            query = params.find("&");
            if (query == std::string::npos)
                query_params[params.substr(0, params.find("="))] = params.substr(params.find("=") + 1);
            else
                while (query != std::string::npos)
                {
                    auto name = params.substr(0, query);
                    auto value = params.substr(query + 1);
                    query_params[name] = value;
                    query = params.find("&");
                }
        }

        std::map<std::string, std::string> headers;
        std::string header;
        std::getline(input, header);
        while (header != "\r")
        {
            auto colon = header.find(": ");
            if (colon != std::string::npos)
            {
                auto name = header.substr(0, colon);
                auto value = header.substr(colon + 2);
                headers[name] = value;
            }
            std::getline(input, header);
        }

        if (method == method::GET)
            return request(socket, method, std::move(path), std::move(version), std::move(headers));
        else if (headers.find("Content-Type") != headers.end() && headers["Content-Type"] == "application/json")
            return json_request(socket, method, std::move(path), std::move(version), std::move(headers), json::load(input));
        else
            return request(socket, method, std::move(path), std::move(version), std::move(headers));
    }
} // namespace network
