#include "server.h"
#include "logging.h"
#include <iostream>

namespace network
{
    RATIONET_EXPORT server::server(short port) : io_service(), acceptor(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)), socket(io_service) {}

    RATIONET_EXPORT void server::add_route(method m, std::regex path, std::function<response_ptr(request &)> callback)
    {
        switch (m)
        {
        case method::GET:
            get_routes.push_back({path, callback});
            break;
        case method::POST:
            post_routes.push_back({path, callback});
            break;
        case method::PUT:
            put_routes.push_back({path, callback});
            break;
        case method::DELETE:
            delete_routes.push_back({path, callback});
            break;
        }
    }

    RATIONET_EXPORT void server::bind(std::string address, short port)
    {
        auto endpoint = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(address), port);
        acceptor.open(endpoint.protocol());
        acceptor.bind(endpoint);
    }

    RATIONET_EXPORT void server::start()
    {
        start_accept();
        LOG("Server started on " << acceptor.local_endpoint().address().to_string() << ":" << acceptor.local_endpoint().port());
        io_service.run();
    }

    RATIONET_EXPORT void server::stop() { io_service.stop(); }

    void server::start_accept()
    {
        acceptor.async_accept(socket, [this](boost::system::error_code ec)
                              {
            if (!ec)
            {
                request req = parse_request(socket);
                LOG_DEBUG("Request:\r\n" << req);

                response_ptr res = handle_request(req);
                boost::asio::streambuf res_buff;
                std::ostream output(&res_buff);
                if (res)
                {
                    if (auto json_res = dynamic_cast<json_response *>(res.operator->()))
                        output << *json_res;
                    else
                        output << *res;
                    socket.async_write_some(res_buff.data(), [this](boost::system::error_code ec, [[maybe_unused]] std::size_t bytes_transferred)
                                             {
                        if (!ec)
                            socket.close();
                    });
                } else {
                    output << response(response_code::NOT_FOUND);
                    socket.async_write_some(res_buff.data(), [this](boost::system::error_code ec, [[maybe_unused]] std::size_t bytes_transferred)
                                             {
                        if (!ec)
                            socket.close();
                    });
                }
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
        std::getline(input, method_str, ' ');
        std::getline(input, path, ' ');
        std::getline(input, version, '\r');
        input.get();

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
            auto name = header.substr(0, colon);
            auto value = header.substr(colon + 2);
            headers[name] = value;
            std::getline(input, header);
        }
        input.get();

        if (method == method::GET)
            return request(method, std::move(path), std::move(version), std::move(headers));
        else if (headers.find("Content-Type") != headers.end())
        {
            if (headers["Content-Type"] == "application/json")
                return json_request(method, std::move(path), std::move(version), std::move(headers), json::load(input));
            else if (headers["Content-Type"] == "text/plain")
            {
                std::string body;
                std::string line;
                std::getline(input, line);
                while (line != "\r")
                {
                    body += line;
                    std::getline(input, line);
                }

                return text_request(method, std::move(path), std::move(version), std::move(headers), std::move(body));
            }
            else
                return request(method, std::move(path), std::move(version), std::move(headers));
        }
        else
            return request(method, std::move(path), std::move(version), std::move(headers));
    }

    response_ptr server::handle_request(request &req)
    {
        switch (req.m)
        {
        case method::GET:
            for (auto &route : get_routes)
                if (std::regex_match(req.path, route.first))
                    return route.second(req);
            break;
        case method::POST:
            for (auto &route : post_routes)
                if (std::regex_match(req.path, route.first))
                    return route.second(req);
            break;
        case method::PUT:
            for (auto &route : put_routes)
                if (std::regex_match(req.path, route.first))
                    return route.second(req);
            break;
        case method::DELETE:
            for (auto &route : delete_routes)
                if (std::regex_match(req.path, route.first))
                    return route.second(req);
            break;
        }

        LOG_WARN("No route found for " << to_string(req.m) << " " << req.path);
        return nullptr;
    }
} // namespace network