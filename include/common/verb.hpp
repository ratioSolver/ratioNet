#pragma once

#include <string>

namespace network
{
  enum verb
  {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Options
  };

  [[nodiscard]] inline std::string to_string(verb v)
  {
    switch (v)
    {
    case Get:
      return "GET";
    case Post:
      return "POST";
    case Put:
      return "PUT";
    case Patch:
      return "PATCH";
    case Delete:
      return "DELETE";
    case Options:
      return "OPTIONS";
    }
    return {};
  }
} // namespace network
