#pragma once

#include <fstream>
#include "status_code.hpp"
#include "mime_types.hpp"
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
      os << version << ' ' << to_string(code) << "\r\n";
      for (const auto &header : headers)
        os << header.first << ": " << header.second << "\r\n";
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
      response::write(os) << "\r\n"
                          << body << "\r\n";
      return os;
    }

  private:
    std::string body;
  };

  class html_response : public response
  {
  public:
    html_response(std::string &&b, status_code code = status_code::ok, std::map<std::string, std::string> &&hdrs = {}, std::string &&ver = "HTTP/1.1") : response(code, std::move(hdrs), std::move(ver)), body(std::move(b))
    {
      headers["Content-Type"] = "text/html";
      headers["Content-Length"] = std::to_string(body.size());
    }

    const std::string &get_body() const { return body; }

  private:
    std::ostream &write(std::ostream &os) const override
    {
      response::write(os) << "\r\n"
                          << body << "\r\n";
      return os;
    }

  private:
    std::string body;
  };

  class file_response : public response
  {
  public:
    file_response(std::string &&file, status_code code = status_code::ok, std::map<std::string, std::string> &&hdrs = {}, std::string &&ver = "HTTP/1.1") : response(code, std::move(hdrs), std::move(ver)), file(std::move(file))
    {
      std::ifstream f(file, std::ios::binary);
      if (!f)
        throw std::invalid_argument("Could not open file: " + file);

      f.seekg(0, std::ios::end);
      headers["Content-Length"] = std::to_string(f.tellg());

      auto ext = file.substr(file.find_last_of('.') + 1);
      headers["Content-Type"] = network::mime_types.at(ext);
    }

    const std::string &get_file() const { return file; }

  private:
    std::ostream &write(std::ostream &os) const override
    {
      response::write(os) << "\r\n";
      std::ifstream
          f(file, std::ios::binary);
      os << f.rdbuf() << "\r\n";
      return os;
    }

  private:
    std::string file;
  };

  class json_response : public response
  {
  public:
    json_response(json::json &&b, status_code code = status_code::ok, std::map<std::string, std::string> &&hdrs = {}, std::string &&ver = "HTTP/1.1") : response(code, std::move(hdrs), std::move(ver)), body(b.to_string())
    {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = body.size();
    }

    const std::string &get_body() const { return body; }

  private:
    std::ostream &write(std::ostream &os) const override
    {
      response::write(os) << "\r\n"
                          << body << "\r\n";
      return os;
    }

  private:
    std::string body;
  };
} // namespace network
