#pragma once

#include <boost/asio.hpp>
#include "verb.hpp"
#include "json.hpp"

namespace network
{
  class session;

  /**
   * @brief Represents an HTTP request.
   */
  class request
  {
    friend class session;

  public:
    /**
     * @brief Default constructor.
     */
    request() = default;

    /**
     * @brief Constructor.
     * @param v The HTTP verb of the request.
     * @param trgt The target of the request.
     * @param ver The HTTP version of the request.
     * @param hdrs The headers of the request.
     */
    request(verb v, std::string &&trgt, std::string &&ver, std::map<std::string, std::string> &&hdrs) : v(v), target(trgt), version(ver), headers(hdrs) {}

    /**
     * @brief Destructor.
     */
    virtual ~request() = default;

    /**
     * @brief Get the HTTP verb of the request.
     * @return The HTTP verb.
     */
    verb get_verb() const { return v; }

    /**
     * @brief Get the target of the request.
     * @return The target.
     */
    const std::string &get_target() const { return target; }

    /**
     * @brief Get the HTTP version of the request.
     * @return The HTTP version.
     */
    const std::string &get_version() const { return version; }

    /**
     * @brief Get the headers of the request.
     * @return The headers.
     */
    const std::map<std::string, std::string> &get_headers() const { return headers; }

    /**
     * @brief Overloaded stream insertion operator to write the request to an output stream.
     * @param os The output stream to write to.
     * @param req The request to write.
     * @return The output stream after writing.
     */
    friend std::ostream &operator<<(std::ostream &os, const request &req) { return req.write(os); }

    /**
     * @brief Get the buffer containing the request.
     * @return The buffer.
     */
    boost::asio::streambuf &get_buffer()
    {
      std::ostream os(&buffer);
      write(os); // Write the request to the buffer
      return buffer;
    }

  protected:
    /**
     * @brief Writes the request object to the output stream.
     * @param os The output stream to write to.
     * @return The output stream after writing.
     */
    virtual std::ostream &write(std::ostream &os) const
    {
      os << to_string(v) << ' ' << target << " " << version << '\n';
      for (const auto &header : headers)
        os << header.first << ": " << header.second << '\n';
      return os;
    }

  private:
    verb v;                                     // The HTTP verb of the request
    std::string target;                         // The target of the request
    std::string version;                        // The HTTP version of the request
    std::map<std::string, std::string> headers; // The headers of the request
    boost::asio::streambuf buffer;              // The buffer containing the request
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
