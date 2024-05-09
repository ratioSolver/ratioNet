#pragma once

#include <string>

namespace network
{
  enum verb
  {
    Get,
    Post,
    Put,
    Delete
  };

  inline std::string to_string(verb v)
  {
    switch (v)
    {
    case Get:
      return "GET";
    case Post:
      return "POST";
    case Put:
      return "PUT";
    case Delete:
      return "DELETE";
    }
    return {};
  }
} // namespace network
