#pragma once

#include "verb.hpp"
#include "json.hpp"
#include <asio.hpp>

namespace network
{
  class client_base;
  class client_session_base;
  class ws_client_session_base;
  class server_session_base;

  namespace placeholders
  {
    static constexpr auto &request = std::placeholders::_1;
  }

  /**
   * @brief Represents an HTTP request.
   */
  class request
  {
    friend class client_base;
    friend class client_session_base;
    friend class ws_client_session_base;
    friend class server_session_base;

  public:
    /**
     * @brief Default constructor.
     */
    request() = default;

    /**
     * @brief Constructor.
     *
     * @param v The HTTP verb of the request.
     * @param trgt The target of the request.
     * @param ver The HTTP version of the request.
     * @param hdrs The headers of the request.
     */
    request(verb v, std::string_view trgt, std::string_view ver, std::multimap<std::string, std::string> &&hdrs) : v(v), target(trgt), version(ver), headers(hdrs) {}
    /**
     * @brief Constructs a request from a stream buffer.
     *
     * @param buf The stream buffer containing the request data.
     */
    explicit request(asio::streambuf &buf)
    {
      std::istream is(&buf);
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
      case 'O':
        if (is.get() == 'P' && is.get() == 'T' && is.get() == 'I' && is.get() == 'O' && is.get() == 'N' && is.get() == 'S')
          v = Options;
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
        target += static_cast<char>(is.get());
      is.get(); // consume space

      while (is.peek() != '\r')
        version += static_cast<char>(is.get());
      is.get(); // consume '\r'
      is.get(); // consume '\n'

      // Read headers
      std::string line;
      while (std::getline(is, line))
      {
        if (!line.empty() && line.back() == '\r')
          line.pop_back(); // Remove trailing '\r' if present (for CRLF line endings)

        if (line.empty())
          break; // Empty line signals end of headers

        if (auto colon = line.find(':'); colon != std::string::npos)
          add_header(line.substr(0, colon), line.substr(colon + 1));
      }
    }
    /**
     * @brief Destructor.
     */
    virtual ~request() = default;

    /**
     * @brief Get the HTTP verb of the request.
     * @return The HTTP verb.
     */
    [[nodiscard]] verb get_verb() const { return v; }

    /**
     * @brief Get the target of the request.
     * @return The target.
     */
    [[nodiscard]] const std::string &get_target() const { return target; }

    /**
     * @brief Get the HTTP version of the request.
     * @return The HTTP version.
     */
    [[nodiscard]] const std::string &get_version() const { return version; }

    /**
     * @brief Get the headers of the request.
     * @return The headers.
     */
    [[nodiscard]] const std::multimap<std::string, std::string> &get_headers() const { return headers; }

    /**
     * @brief Adds a header to the request.
     *
     * @param header The header key.
     * @param value The header value.
     */
    void add_header(std::string_view header, std::string_view value)
    {
      // Normalize header to lowercase
      std::string header_str(header);
      std::transform(header_str.begin(), header_str.end(), header_str.begin(), [](unsigned char c)
                     { return std::tolower(c); });

      // Trim whitespace from value
      std::string value_str(value);
      size_t start = value_str.find_first_not_of(" \t");
      size_t end = value_str.find_last_not_of(" \t");
      if (start != std::string::npos && end != std::string::npos)
        value_str = value_str.substr(start, end - start + 1);
      else // value is all whitespace
        value_str.clear();

      headers.emplace(std::move(header_str), std::move(value_str));
    }

    /**
     * Checks if the request is an upgrade request for a WebSocket connection.
     *
     * @return true if the request is an upgrade request for a WebSocket connection, false otherwise.
     */
    [[nodiscard]] bool is_upgrade() const
    {
      auto upgrade_it = headers.find("upgrade");
      if (upgrade_it == headers.end())
        return false;
      auto connection_it = headers.find("connection");
      if (connection_it == headers.end())
        return false;
      // Case-insensitive compare for 'websocket' and 'upgrade'
      return std::equal(upgrade_it->second.begin(), upgrade_it->second.end(), "websocket", [](char a, char b)
                        { return std::tolower(a) == std::tolower(b); }) &&
             std::equal(connection_it->second.begin(), connection_it->second.end(), "upgrade", [](char a, char b)
                        { return std::tolower(a) == std::tolower(b); });
    }

    /**
     * Checks if the request is a keep-alive request.
     * A keep-alive request is determined by the presence of the "Connection" header
     * with a value of "keep-alive".
     *
     * @return true if the request is a keep-alive request, false otherwise.
     */
    [[nodiscard]] bool is_keep_alive() const
    {
      auto connection_it = headers.find("connection");
      if (connection_it == headers.end())
        return false;
      return std::equal(connection_it->second.begin(), connection_it->second.end(), "keep-alive", [](char a, char b)
                        { return std::tolower(a) == std::tolower(b); });
    }

    /**
     * Checks if the request uses chunked transfer encoding.
     * A request is considered chunked if it contains the "Transfer-Encoding" header
     * with a value of "chunked".
     *
     * @return true if the request uses chunked transfer encoding, false otherwise.
     */
    [[nodiscard]] bool is_chunked() const
    {
      auto te_it = headers.find("transfer-encoding");
      if (te_it == headers.end())
        return false;
      return std::equal(te_it->second.begin(), te_it->second.end(), "chunked", [](char a, char b)
                        { return std::tolower(a) == std::tolower(b); });
    }

    /**
     * Checks if the request has a JSON content type.
     * A request is considered to have a JSON content type if it contains the "Content-Type" header
     * with a value of "application/json".
     *
     * @return true if the request has a JSON content type, false otherwise.
     */
    [[nodiscard]] bool is_json() const
    {
      auto ct_it = headers.find("content-type");
      if (ct_it == headers.end())
        return false;
      return ct_it->second.find("application/json") != std::string::npos;
    }

    /**
     * @brief Overloaded stream insertion operator to write the request to an output stream.
     * @param os The output stream to write to.
     * @param req The request to write.
     * @return The output stream after writing.
     */
    friend std::ostream &operator<<(std::ostream &os, const request &req) { return req.write(os); }

  private:
    /**
     * @brief Get the buffer containing the request.
     * @return The buffer.
     */
    [[nodiscard]] asio::streambuf &get_buffer()
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
      os << to_string(v) << ' ' << target << " " << version << "\r\n";
      for (const auto &header : headers)
        os << header.first << ": " << header.second << "\r\n";
      os << "\r\n";
      return os;
    }

  private:
    verb v;                                          // The HTTP verb of the request
    std::string target;                              // The target of the request
    std::string version;                             // The HTTP version of the request
    std::multimap<std::string, std::string> headers; // The headers of the request
    asio::streambuf buffer;                          // The buffer containing the request
    std::string accumulated_body;                    // Accumulated body for chunked requests
  };

  class string_request : public request
  {
  public:
    string_request(verb v, std::string_view trgt, std::string_view ver, std::multimap<std::string, std::string> &&hdrs, std::string &&b) : request(v, std::move(trgt), std::move(ver), std::move(hdrs)), body(std::move(b))
    {
      add_header("content-type", "text/plain");
      add_header("content-length", std::to_string(body.size()));
    }

    const std::string &get_body() const { return body; }

  private:
    std::ostream &write(std::ostream &os) const override
    {
      request::write(os) << body;
      return os;
    }

  private:
    std::string body;
  };

  class json_request : public request
  {
  public:
    json_request(verb v, std::string_view trgt, std::string_view ver, std::multimap<std::string, std::string> &&hdrs, json::json &&b) : request(v, std::move(trgt), std::move(ver), std::move(hdrs)), body(b), str_body(body.dump())
    {
      add_header("content-type", "application/json");
      add_header("content-length", std::to_string(str_body.size()));
    }

    const json::json &get_body() const { return body; }

  private:
    std::ostream &write(std::ostream &os) const override
    {
      request::write(os) << str_body;
      return os;
    }

  private:
    json::json body;      // The JSON body of the request
    std::string str_body; // The body of the request
  };
} // namespace network
