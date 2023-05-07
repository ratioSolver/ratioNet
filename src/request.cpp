#include "request.h"

namespace network
{
    request::request(method m, std::string path, std::string version, std::map<std::string, std::string> headers) : m(m), path(path), version(version), headers(headers) {}

    json_request::json_request(method m, std::string path, std::string version, std::map<std::string, std::string> headers, json::json body) : request(m, path, version, headers), body(std::move(body)) {}
} // namespace network
