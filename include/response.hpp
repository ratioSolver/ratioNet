#pragma once

#include "status_code.hpp"
#include "json.hpp"

namespace network
{
  class response
  {
  public:
    response(status_code code = status_code::ok, std::map<std::string, std::string> &&hdrs = {}, std::string &&ver = "HTTP/1.1") : code(code), headers(hdrs), version(ver) {}

    status_code get_status_code() const { return code; }
    const std::map<std::string, std::string> &get_headers() const { return headers; }
    const std::string &get_version() const { return version; }

    friend std::ostream &operator<<(std::ostream &os, const response &res) { return res.write(os); }

  protected:
    /**
     * Writes the object to the output stream.
     *
     * @param os The output stream to write to.
     * @return A reference to the output stream after writing.
     */
    virtual std::ostream &write(std::ostream &os) const
    {
      os << version << ' ' << to_string(code) << '\n';
      for (const auto &header : headers)
        os << header.first << ": " << header.second << '\n';
      return os;
    }

  private:
    status_code code;

  protected:
    std::map<std::string, std::string> headers;

  private:
    std::string version;
  };

  class string_response : public response
  {
  public:
    string_response(std::string &&b, status_code code = status_code::ok, std::map<std::string, std::string> &&hdrs = {}, std::string &&ver = "HTTP/1.1") : response(code, std::move(hdrs), std::move(ver)), body(std::move(b))
    {
      headers["Content-Type"] = "text/plain";
      headers["Content-Length"] = std::to_string(body.size());
    }

    const std::string &get_body() const { return body; }

  private:
    std::ostream &write(std::ostream &os) const override
    {
      response::write(os) << '\n'
                          << body << '\n';
      return os;
    }

  private:
    std::string body;
  };

  class json_response : public response
  {
  public:
    json_response(json::json &&b, status_code code = status_code::ok, std::map<std::string, std::string> &&hdrs = {}, std::string &&ver = "HTTP/1.1") : response(code, std::move(hdrs), std::move(ver)), body(std::move(b))
    {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = body.to_string().size();
    }

    const json::json &get_body() const { return body; }

  private:
    std::ostream &write(std::ostream &os) const override
    {
      response::write(os) << '\n'
                          << body << '\n';
      return os;
    }

  private:
    json::json body;
  };
} // namespace network
