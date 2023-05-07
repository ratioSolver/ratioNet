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

    friend std::ostream &operator<<(std::ostream &os, const request &r);

    method m;
    std::string path, version;
    std::map<std::string, std::string> headers;
  };

  class text_request : public request
  {
  public:
    text_request(method m, std::string path, std::string version, std::map<std::string, std::string> headers, std::string body);

    friend std::ostream &operator<<(std::ostream &os, const text_request &r);

    std::string body;
  };

  class json_request : public request
  {
  public:
    json_request(method m, std::string path, std::string version, std::map<std::string, std::string> headers, json::json body);

    friend std::ostream &operator<<(std::ostream &os, const json_request &r);

    json::json body;
  };
} // namespace network
