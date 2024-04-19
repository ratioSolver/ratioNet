#pragma once

#include <boost/asio.hpp>
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

    friend std::ostream &operator<<(std::ostream &os, const request &req) { return req.write(os); }

  protected:
    /**
     * Writes the object to the output stream.
     *
     * @param os The output stream to write to.
     * @return A reference to the output stream after writing.
     */
    virtual std::ostream &write(std::ostream &os) const
    {
      os << to_string(v) << ' ' << target << " " << version << '\n';
      for (const auto &header : headers)
        os << header.first << ": " << header.second << '\n';
      return os;
    }

  private:
    verb v;
    std::string target, version;
    std::map<std::string, std::string> headers;
    boost::asio::streambuf buffer;
  };

  class string_request : public request
  {
  public:
    string_request(verb v, std::string &&trgt, std::string &&ver, std::map<std::string, std::string> &&hdrs, std::string &&b) : request(v, std::move(trgt), std::move(ver), std::move(hdrs)), body(std::move(b)) {}

    const std::string &get_body() const { return body; }

  private:
    std::ostream &write(std::ostream &os) const override
    {
      request::write(os) << '\n'
                         << body << '\n';
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

  private:
    std::ostream &write(std::ostream &os) const override
    {
      request::write(os) << '\n'
                         << body << '\n';
      return os;
    }

  private:
    json::json body;
  };
} // namespace network
