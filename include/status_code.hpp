#pragma once

#include <string>

namespace network
{
  enum status_code
  {
    websocket_switching_protocols = 101,
    ok = 200,
    created = 201,
    accepted = 202,
    no_content = 204,
    multiple_choices = 300,
    moved_permanently = 301,
    moved_temporarily = 302,
    not_modified = 304,
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    conflict = 409,
    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503
  };

  inline std::string to_string(status_code code)
  {
    switch (code)
    {
    case websocket_switching_protocols:
      return "101 Switching Protocols";
    case ok:
      return "200 OK";
    case created:
      return "201 Created";
    case accepted:
      return "202 Accepted";
    case no_content:
      return "204 No Content";
    case multiple_choices:
      return "300 Multiple Choices";
    case moved_permanently:
      return "301 Moved Permanently";
    case moved_temporarily:
      return "302 Moved Temporarily";
    case not_modified:
      return "304 Not Modified";
    case bad_request:
      return "400 Bad Request";
    case unauthorized:
      return "401 Unauthorized";
    case forbidden:
      return "403 Forbidden";
    case not_found:
      return "404 Not Found";
    case conflict:
      return "409 Conflict";
    case internal_server_error:
      return "500 Internal Server Error";
    case not_implemented:
      return "501 Not Implemented";
    case bad_gateway:
      return "502 Bad Gateway";
    case service_unavailable:
      return "503 Service Unavailable";
    default:
      return "Unknown status code";
    }
  }
} // namespace network
