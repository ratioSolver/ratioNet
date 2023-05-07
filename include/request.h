#pragma once

#include "json.h"

namespace network
{
  enum method
  {
    GET,
    POST,
    PUT,
    DELETE
  };

  inline std::string to_string(method m) noexcept
  {
    switch (m)
    {
    case GET:
      return "GET";
    case POST:
      return "POST";
    case PUT:
      return "PUT";
    case DELETE:
      return "DELETE";
    default:
      return "UNKNOWN";
    }
  }

  class request
  {
  public:
    request(method m, std::string path, std::string version, std::map<std::string, std::string> headers);
    virtual ~request() = default;

    method m;
    std::string path, version;
    std::map<std::string, std::string> headers;
  };

  class json_request : public request
  {
  public:
    json_request(method m, std::string path, std::string version, std::map<std::string, std::string> headers, json::json body);

    json::json body;
  };
} // namespace network
