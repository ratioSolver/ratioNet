#include "request.h"

namespace network
{
    RATIONET_EXPORT request::request(method m, std::string path, std::map<std::string, std::string> headers) : m(m), path(path), headers(headers) {}

    RATIONET_EXPORT std::ostream &operator<<(std::ostream &os, const request &r)
    {
        os << to_string(r.m) << " " << r.path << " " << r.version << "\r\n";
        for (auto &header : r.headers)
            os << header.first << ": " << header.second << "\r\n";
        os << "\r\n";
        return os;
    }

    RATIONET_EXPORT text_request::text_request(method m, std::string path, std::map<std::string, std::string> headers, std::string body) : request(m, path, headers), body(std::move(body)) {}

    RATIONET_EXPORT std::ostream &operator<<(std::ostream &os, const text_request &r)
    {
        os << static_cast<const request &>(r);
        os << r.body << "\r\n";
        return os;
    }

    RATIONET_EXPORT json_request::json_request(method m, std::string path, std::map<std::string, std::string> headers, json::json body) : request(m, path, headers), body(std::move(body)) {}

    RATIONET_EXPORT std::ostream &operator<<(std::ostream &os, const json_request &r)
    {
        os << static_cast<const request &>(r);
        os << r.body << "\r\n";
        return os;
    }
} // namespace network
