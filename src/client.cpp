#include "client.h"

namespace network
{
    client::client(std::string host, std::string port) : endpoints(boost::asio::ip::tcp::resolver(io_service).resolve(host, port)), socket(io_service) {}

    response_ptr client::call(const request &req)
    {
        boost::asio::connect(socket, endpoints);

        boost::asio::streambuf req_buff;
        std::ostream req_strm(&req_buff);

        req_strm << req;

        boost::asio::write(socket, req_buff);

        boost::asio::streambuf resp_buff;
        boost::asio::read_until(socket, resp_buff, "\r\n");

        std::istream resp_strm(&resp_buff);
        std::string http_version;
        resp_strm >> http_version;

        unsigned int status_code;
        resp_strm >> status_code;

        std::string status_message;
        std::getline(resp_strm, status_message);

        if (!resp_strm || http_version.substr(0, 5) != "HTTP/")
            throw std::runtime_error("Invalid response");

        boost::asio::read_until(socket, resp_buff, "\r\n\r\n");

        std::map<std::string, std::string> headers;
        std::string header;
        while (std::getline(resp_strm, header) && header != "\r")
        {
            auto colon = header.find(": ");
            headers[header.substr(0, colon)] = header.substr(colon + 2);
        }

        if (auto ct_it = headers.find("Content-Type"); ct_it != headers.end())
        {
            if (ct_it->second == "application/json")
                return new json_response(json::load(resp_strm), status_code, status_message);
            else if (ct_it->second == "text/html" || ct_it->second == "text/plain")
            {
                std::string body;
                std::string line;
                while (std::getline(resp_strm, line))
                    body += line;
                return new text_response(body, status_code, status_message);
            }
            else
                return new response(status_code, status_message);
        }

        return new response(status_code, status_message);
    }

} // namespace network
