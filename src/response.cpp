#include "response.h"
#include <fstream>

namespace network
{
    RATIONET_EXPORT response::response(response_code code) : response(code, to_string(code)) {}
    RATIONET_EXPORT response::response(int status_code, std::string status_message) : status_code(status_code), status_message(status_message) {}

    RATIONET_EXPORT std::ostream &operator<<(std::ostream &os, const response &res)
    {
        os << "HTTP/1.1 " << res.status_code << " " << res.status_message << "\r\n";
        for (auto &[name, value] : res.headers)
            os << name << ": " << value << "\r\n";
        os << "\r\n";
        return os;
    }

    RATIONET_EXPORT json_response::json_response(json::json body, response_code code) : json_response(std::move(body), code, to_string(code)) {}
    RATIONET_EXPORT json_response::json_response(json::json body, int status_code, std::string status_message) : response(status_code, status_message), body(std::move(body))
    {
        headers["Content-Type"] = "application/json";
    }

    RATIONET_EXPORT std::ostream &operator<<(std::ostream &os, const json_response &res)
    {
        os << static_cast<const response &>(res);
        os << res.body;
        return os;
    }

    RATIONET_EXPORT text_response::text_response(std::string body, response_code code) : text_response(std::move(body), code, to_string(code)) {}
    RATIONET_EXPORT text_response::text_response(std::string body, int status_code, std::string status_message) : response(status_code, status_message), body(std::move(body))
    {
        headers["Content-Type"] = "text/plain";
    }

    RATIONET_EXPORT std::ostream &operator<<(std::ostream &os, const text_response &res)
    {
        os << static_cast<const response &>(res);
        os << res.body;
        return os;
    }

    RATIONET_EXPORT file_response::file_response(std::string path, response_code code) : file_response(std::move(path), code, to_string(code)) {}
    RATIONET_EXPORT file_response::file_response(std::string path, int status_code, std::string status_message) : response(status_code, status_message), path(std::move(path))
    {
        headers["Content-Type"] = "application/octet-stream";
    }

    RATIONET_EXPORT std::ostream &operator<<(std::ostream &os, const file_response &res)
    {
        os << static_cast<const response &>(res);
        std::ifstream file(res.path, std::ios::binary);
        os << file.rdbuf();
        return os;
    }
} // namespace network
