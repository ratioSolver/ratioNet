#pragma once

#include "verb.hpp"
#include "json.hpp"

namespace network
{
  class session;

  class request
  {
    friend class session;

  public:
    request() = default;
    request(verb v, std::string &&trgt, std::string &&ver, std::map<std::string, std::string> &&hdrs) : v(v), target(trgt), version(ver), headers(hdrs) {}
    virtual ~request() = default;

    verb get_verb() const { return v; }
    const std::string &get_target() const { return target; }
    const std::string &get_version() const { return version; }
    const std::map<std::string, std::string> &get_headers() const { return headers; }

    friend std::ostream &operator<<(std::ostream &os, const request &req)
    {
      os << to_string(req.v) << ' ' << req.target << " " << req.version << '\n';
      for (const auto &header : req.headers)
        os << header.first << ": " << header.second << '\n';
      return os;
    }

  private:
    verb v;
    std::string target, version;
    std::map<std::string, std::string> headers;
  };

  class string_request : public request
  {
  public:
    string_request(verb v, std::string &&trgt, std::string &&ver, std::map<std::string, std::string> &&hdrs, std::string &&b) : request(v, std::move(trgt), std::move(ver), std::move(hdrs)), body(std::move(b)) {}

    const std::string &get_body() const { return body; }

    friend std::ostream &operator<<(std::ostream &os, const string_request &req)
    {
      os << static_cast<const request &>(req) << '\n'
         << req.body << '\n';
      return os;
    }

  private:
    std::string body;
  };

  class json_request : public request
  {
  public:
    json_request(verb v, std::string &&trgt, std::string &&ver, std::map<std::string, std::string> &&hdrs, json::json &&b) : request(v, std::move(trgt), std::move(ver), std::move(hdrs)), body(std::move(b)) {}

    const json::json &get_body() const { return body; }

    friend std::ostream &operator<<(std::ostream &os, const json_request &req)
    {
      os << static_cast<const request &>(req) << '\n'
         << req.body << '\n';
      return os;
    }

  private:
    json::json body;
  };
} // namespace network
