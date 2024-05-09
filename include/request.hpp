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
     * Checks if the request is an upgrade request for a WebSocket connection.
     *
     * @return true if the request is an upgrade request for a WebSocket connection, false otherwise.
     */
    bool is_upgrade() const { return headers.find("Upgrade") != headers.end() && headers.at("Upgrade") == "websocket"; }

    /**
     * Checks if the request is a keep-alive request.
     * A keep-alive request is determined by the presence of the "Connection" header
     * with a value of "keep-alive".
     *
     * @return true if the request is a keep-alive request, false otherwise.
     */
    bool is_keep_alive() const { return headers.find("Connection") != headers.end() && headers.at("Connection") == "keep-alive"; }

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

    /**
     * @brief Parses the request.
     *
     * This function is responsible for parsing the request.
     * It performs the necessary operations to extract relevant information from the request.
     */
    void parse()
    {
      std::istream is(&buffer);
      switch (is.get())
      {
      case 'D':
        if (is.get() == 'E' && is.get() == 'L' && is.get() == 'E' && is.get() == 'T' && is.get() == 'E')
          v = Delete;
        break;
      case 'G':
        if (is.get() == 'E' && is.get() == 'T')
          v = Get;
        break;
      case 'P':
        switch (is.get())
        {
        case 'O':
          if (is.get() == 'S' && is.get() == 'T')
            v = Post;
          break;
        case 'U':
          if (is.get() == 'T')
            v = Put;
          break;
        }
        break;
      }
      is.get(); // consume space

      while (is.peek() != ' ')
        target += is.get();
      is.get(); // consume space

      while (is.peek() != '\r')
        version += is.get();
      is.get(); // consume '\r'
      is.get(); // consume '\n'

      while (is.peek() != '\r')
      {
        std::string header, value;
        while (is.peek() != ':')
          header += is.get();
        is.get(); // consume ':'
        is.get(); // consume space
        while (is.peek() != '\r')
          value += is.get();
        is.get(); // consume '\r'
        is.get(); // consume '\n'
        headers.emplace(std::move(header), std::move(value));
      }
      is.get(); // consume '\r'
      is.get(); // consume '\n'
    }

  protected:
    /**
     * @brief Writes the request object to the output stream.
     * @param os The output stream to write to.
     * @return The output stream after writing.
     */
    virtual std::ostream &write(std::ostream &os) const
    {
      os << to_string(v) << ' ' << target << " " << version << "\r\n";
      for (const auto &header : headers)
        os << header.first << ": " << header.second << "\r\n";
      os << "\r\n";
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
      request::write(os) << "\r\n"
                         << body << "\r\n";
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
      request::write(os) << "\r\n"
                         << body << "\r\n";
      return os;
    }

  private:
    json::json body;
  };
} // namespace network
