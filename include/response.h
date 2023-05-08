#pragma once

#include "rationet_export.h"
#include "json.h"
#include "memory.h"

namespace network
{
  class response;

  enum response_code
  {
    OK = 200,
    CREATED = 201,
    ACCEPTED = 202,
    NO_CONTENT = 204,
    MOVED_PERMANENTLY = 301,
    FOUND = 302,
    NOT_MODIFIED = 304,
    BAD_REQUEST = 400,
    UNAUTHORIZED = 401,
    FORBIDDEN = 403,
    NOT_FOUND = 404,
    METHOD_NOT_ALLOWED = 405,
    INTERNAL_SERVER_ERROR = 500,
    NOT_IMPLEMENTED = 501,
    BAD_GATEWAY = 502,
    SERVICE_UNAVAILABLE = 503
  };

  inline std::string to_string(response_code code) noexcept
  {
    switch (code)
    {
    case OK:
      return "OK";
    case CREATED:
      return "Created";
    case ACCEPTED:
      return "Accepted";
    case NO_CONTENT:
      return "No Content";
    case MOVED_PERMANENTLY:
      return "Moved Permanently";
    case FOUND:
      return "Found";
    case NOT_MODIFIED:
      return "Not Modified";
    case BAD_REQUEST:
      return "Bad Request";
    case UNAUTHORIZED:
      return "Unauthorized";
    case FORBIDDEN:
      return "Forbidden";
    case NOT_FOUND:
      return "Not Found";
    case METHOD_NOT_ALLOWED:
      return "Method Not Allowed";
    case INTERNAL_SERVER_ERROR:
      return "Internal Server Error";
    case NOT_IMPLEMENTED:
      return "Not Implemented";
    case BAD_GATEWAY:
      return "Bad Gateway";
    case SERVICE_UNAVAILABLE:
      return "Service Unavailable";
    }
    return "Unknown";
  }

  class response
  {
  public:
    RATIONET_EXPORT response(response_code code = OK);
    RATIONET_EXPORT response(unsigned int status_code, std::string status_message);
    virtual ~response() = default;

    RATIONET_EXPORT friend std::ostream &operator<<(std::ostream &os, const response &res);

    unsigned int status_code;
    std::string status_message;
    std::map<std::string, std::string> headers;
  };
  using response_ptr = utils::u_ptr<response>;

  class json_response : public response
  {
  public:
    RATIONET_EXPORT json_response(json::json body = json::json(), response_code code = OK);
    RATIONET_EXPORT json_response(json::json body, unsigned int status_code, std::string status_message);

    RATIONET_EXPORT friend std::ostream &operator<<(std::ostream &os, const json_response &res);

    json::json body;
  };

  class text_response : public response
  {
  public:
    RATIONET_EXPORT text_response(std::string body = "", response_code code = OK);
    RATIONET_EXPORT text_response(std::string body, unsigned int status_code, std::string status_message);

    RATIONET_EXPORT friend std::ostream &operator<<(std::ostream &os, const text_response &res);

    std::string body;
  };

  class file_response : public response
  {
  public:
    RATIONET_EXPORT file_response(std::string path, response_code code = OK);
    RATIONET_EXPORT file_response(std::string path, unsigned int status_code, std::string status_message);

    RATIONET_EXPORT friend std::ostream &operator<<(std::ostream &os, const file_response &res);

    std::string path;
  };
} // namespace network
