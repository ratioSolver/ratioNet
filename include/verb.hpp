#pragma once

#include <string>

namespace network
{
  enum verb
  {
    GET,
    POST,
    PUT,
    DELETE
  };

  inline std::string to_string(verb v)
  {
    switch (v)
    {
    case GET:
      return "GET";
    case POST:
      return "POST";
    case PUT:
      return "PUT";
    case DELETE:
      return "DELETE";
    }
    return {};
  }
} // namespace network
