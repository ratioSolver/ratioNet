#pragma once

#include "status_code.hpp"
#include "mime_types.hpp"
#include "json.hpp"
#include <asio.hpp>
#include <fstream>

namespace network
{
  class client_base;
  class client_session_base;
  class ws_client_session_base;
  class server_session_base;

  /**
   * @brief Represents an HTTP response.
   */
  class response
  {
    friend class client_base;
    friend class client_session_base;
    friend class ws_client_session_base;
    friend class server_session_base;

  public:
    /**
     * @brief Constructs a response object.
     *
     * @param code The status code of the response.
     * @param hdrs The headers of the response.
     * @param ver The HTTP version of the response.
     */
    response(status_code code = status_code::ok, std::multimap<std::string, std::string> &&hdrs = {}, std::string &&ver = "HTTP/1.1") : code(code), headers(hdrs), version(ver) {}
    /**
     * @brief Constructs a response object from a stream buffer.
     *
     * @param buff The stream buffer containing the response data.
     */
    explicit response(asio::streambuf &buff)
    {
      std::istream is(&buff);

      std::string c_version;
      while (is.peek() != ' ')
        c_version += static_cast<char>(is.get());
      version = std::move(c_version);
      is.get(); // consume ' '
      std::string c_code;
      while (is.peek() != ' ' && is.peek() != '\r')
        c_code += static_cast<char>(is.get());
      code = static_cast<status_code>(std::stoi(c_code));
      if (is.peek() == ' ')
      {
        is.get(); // consume ' '
        std::string c_reason;
        while (is.peek() != '\r')
          c_reason += static_cast<char>(is.get());
      }
      is.get(); // consume '\r'
      is.get(); // consume '\n'

      while (is.peek() != '\r')
      {
        std::string header, value;
        while (is.peek() != ':')
          header += static_cast<char>(is.get());
        is.get(); // consume ':'
        is.get(); // consume space
        while (is.peek() != '\r')
          value += static_cast<char>(is.get());
        is.get(); // consume '\r'
        is.get(); // consume '\n'

        add_header(header, value);
      }
      is.get(); // consume '\r'
      is.get(); // consume '\n'
    }
    virtual ~response() = default;

    /**
     * @brief Gets the status code of the response.
     *
     * @return The status code.
     */
    [[nodiscard]] status_code get_status_code() const { return code; }

    /**
     * @brief Gets the HTTP version of the response.
     *
     * @return The HTTP version.
     */
    [[nodiscard]] const std::string &get_version() const { return version; }

    /**
     * @brief Gets the headers of the response.
     *
     * @return The headers.
     */
    [[nodiscard]] const std::multimap<std::string, std::string> &get_headers() const { return headers; }

    /**
     * @brief Adds a header to the response.
     *
     * @param key The header key.
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
     * @brief Checks if the response uses chunked transfer encoding.
     *
     * This function examines the "transfer-encoding" header in the response.
     * If the header exists and its value is "chunked" (case-insensitive),
     * the function returns true, indicating that the response is chunked.
     *
     * @return true if the "transfer-encoding" header is set to "chunked", false otherwise.
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
     * @brief Checks if the response content type is JSON.
     *
     * This function examines the headers to determine if the "content-type"
     * header contains "application/json". Returns true if the header exists
     * and indicates JSON content, otherwise returns false.
     *
     * @return true if the content type is JSON, false otherwise.
     */
    [[nodiscard]] bool is_json() const
    {
      auto ct_it = headers.find("content-type");
      if (ct_it == headers.end())
        return false;
      return ct_it->second.find("application/json") != std::string::npos;
    }

    /**
     * Checks if the response indicates that the connection should be closed.
     * A response is considered to indicate a closed connection if it contains the "Connection" header
     * with a value of "close".
     *
     * @return true if the response indicates a closed connection, false otherwise.
     */
    [[nodiscard]] bool is_closed() const
    {
      auto connection_it = headers.find("connection");
      if (connection_it == headers.end())
        return false;
      return std::equal(connection_it->second.begin(), connection_it->second.end(), "close", [](char a, char b)
                        { return std::tolower(a) == std::tolower(b); });
    }

    /**
     * @brief Writes the response to an output stream.
     *
     * @param os The output stream to write to.
     * @return A reference to the output stream after writing.
     */
    friend std::ostream &operator<<(std::ostream &os, const response &res) { return res.write(os); }

  private:
    /**
     * @brief Gets the buffer containing the response.
     *
     * @return The buffer.
     */
    [[nodiscard]] asio::streambuf &get_buffer()
    {
      std::ostream os(&buffer);
      write(os); // Write the response to the buffer
      return buffer;
    }

  protected:
    /**
     * @brief Writes the response to an output stream.
     *
     * @param os The output stream to write to.
     * @return A reference to the output stream after writing.
     */
    virtual std::ostream &write(std::ostream &os) const
    {
      os << version << ' ' << to_string(code) << "\r\n";
      for (const auto &header : headers)
        os << header.first << ": " << header.second << "\r\n";
      os << "\r\n";
      return os;
    }

  private:
    status_code code; // The status code of the response

  protected:
    std::multimap<std::string, std::string> headers; // The headers of the response

  private:
    std::string version;          // The HTTP version of the response
    asio::streambuf buffer;       // The buffer containing the response
    std::string accumulated_body; // Accumulated body for chunked responses
  };

  /**
   * @brief A class representing a string response.
   *
   * This class inherits from the base class response and provides functionality to handle string responses.
   */
  class string_response final : public response
  {
  public:
    /**
     * @brief Constructs a string_response object.
     *
     * @param b The body of the response.
     * @param code The status code of the response. Default is status_code::ok.
     * @param hdrs The headers of the response. Default is an empty map.
     * @param ver The version of the response. Default is "HTTP/1.1".
     */
    string_response(std::string &&b, status_code code = status_code::ok, std::multimap<std::string, std::string> &&hdrs = {}, std::string &&ver = "HTTP/1.1") : response(code, std::move(hdrs), std::move(ver)), body(std::move(b))
    {
      add_header("content-type", "text/plain");
      add_header("content-length", std::to_string(body.size()));
    }

    /**
     * @brief Get the body of the response.
     *
     * @return const std::string& The body of the response.
     */
    const std::string &get_body() const { return body; }

  private:
    /**
     * @brief Writes the response to an output stream.
     *
     * @param os The output stream to write to.
     * @return std::ostream& The output stream after writing the response.
     */
    std::ostream &write(std::ostream &os) const override
    {
      response::write(os) << body;
      return os;
    }

  private:
    std::string body; // The body of the response
  };

  /**
   * @brief Represents an HTML response.
   *
   * This class inherits from the base response class and provides functionality to handle HTML responses.
   */
  class html_response final : public response
  {
  public:
    /**
     * @brief Constructs an HTML response object.
     *
     * @param b The body of the response.
     * @param code The status code of the response (default: status_code::ok).
     * @param hdrs The headers of the response (default: empty map).
     * @param ver The HTTP version of the response (default: "HTTP/1.1").
     */
    html_response(std::string &&b, status_code code = status_code::ok, std::multimap<std::string, std::string> &&hdrs = {}, std::string &&ver = "HTTP/1.1") : response(code, std::move(hdrs), std::move(ver)), body(std::move(b))
    {
      add_header("content-type", "text/html");
      add_header("content-length", std::to_string(body.size()));
    }

    /**
     * @brief Gets the body of the response.
     *
     * @return A constant reference to the body of the response.
     */
    const std::string &get_body() const { return body; }

  private:
    /**
     * @brief Writes the HTML response to an output stream.
     *
     * This function overrides the base response class's write function to include the body of the HTML response.
     *
     * @param os The output stream to write the response to.
     * @return The modified output stream.
     */
    std::ostream &write(std::ostream &os) const override
    {
      response::write(os) << body;
      return os;
    }

  private:
    std::string body; // The body of the response
  };

  /**
   * @brief Represents a response that sends a file to the client.
   *
   * The `file_response` class is a derived class of the `response` class. It represents a response that sends a file to the client.
   * It takes the path to the file as a parameter and automatically sets the appropriate headers, such as content-length and content-type.
   */
  class file_response final : public response
  {
  public:
    /**
     * @brief Constructs a `file_response` object with the specified file path, status code, headers, and HTTP version.
     *
     * @param file The path to the file to send.
     * @param code The status code of the response. Default is `status_code::ok`.
     * @param hdrs The headers of the response. Default is an empty map.
     * @param ver The HTTP version of the response. Default is "HTTP/1.1".
     *
     * @throws std::invalid_argument If the file cannot be opened.
     */
    file_response(std::string &&f, status_code code = status_code::ok, std::multimap<std::string, std::string> &&hdrs = {}, std::string &&ver = "HTTP/1.1") : response(code, std::move(hdrs), std::move(ver)), file(std::move(f))
    {
      std::ifstream fs(file, std::ios::binary);
      if (!fs)
        throw std::invalid_argument("Could not open file: " + file);

      fs.seekg(0, std::ios::end);
      add_header("content-length", std::to_string(fs.tellg()));

      if (headers.find("content-type") == headers.end())
      { // If content-type is not set, try to determine it from the file extension..
        auto ext = file.substr(file.find_last_of('.') + 1);
        if (auto ct_it = mime_types.find(ext); ct_it != mime_types.end())
          add_header("content-type", ct_it->second);
        else // Default content type if not found..
          add_header("content-type", "text/plain");
      }
    }

    /**
     * @brief Gets the path to the file.
     *
     * @return The path to the file.
     */
    const std::string &get_file() const { return file; }

  private:
    /**
     * @brief Writes the response to the output stream.
     *
     * This function is called internally to write the response to the output stream.
     *
     * @param os The output stream to write to.
     * @return The output stream after writing the response.
     */
    std::ostream &write(std::ostream &os) const override
    {
      response::write(os);
      std::ifstream f(file, std::ios::binary);
      os << f.rdbuf();
      return os;
    }

  private:
    std::string file; // The path to the file to send
  };

  /**
   * @brief Represents a JSON response in an HTTP server.
   *
   * The `json_response` class is a derived class of the `response` class and is used to represent
   * a JSON response in an HTTP server. It contains the JSON body of the response and provides
   * methods to retrieve the body and write the response to an output stream.
   */
  class json_response final : public response
  {
  public:
    /**
     * @brief Constructs a `json_response` object with the given JSON body, status code, headers, and version.
     *
     * @param b The JSON body of the response.
     * @param code The status code of the response. Default is `status_code::ok`.
     * @param hdrs The headers of the response. Default is an empty map.
     * @param ver The version of the HTTP protocol. Default is "HTTP/1.1".
     */
    json_response(json::json &&b, status_code code = status_code::ok, std::multimap<std::string, std::string> &&hdrs = {}, std::string &&ver = "HTTP/1.1") : response(code, std::move(hdrs), std::move(ver)), body(std::move(b)), str_body(body.dump())
    {
      add_header("content-type", "application/json");
      add_header("content-length", std::to_string(str_body.size()));
    }
    /**
     * @brief Constructs a `json_response` object with the given JSON body, status code, headers, and version.
     *
     * @param b The JSON body of the response.
     * @param code The status code of the response. Default is `status_code::ok`.
     * @param hdrs The headers of the response. Default is an empty map.
     * @param ver The version of the HTTP protocol. Default is "HTTP/1.1".
     */
    json_response(const json::json &b, status_code code = status_code::ok, std::multimap<std::string, std::string> &&hdrs = {}, std::string &&ver = "HTTP/1.1") : response(code, std::move(hdrs), std::move(ver)), body(b), str_body(body.dump())
    {
      add_header("content-type", "application/json");
      add_header("content-length", std::to_string(str_body.size()));
    }

    /**
     * @brief Gets the JSON body of the response.
     *
     * @return The JSON body.
     */
    const json::json &get_body() const { return body; }

  private:
    /**
     * @brief Writes the response to an output stream.
     *
     * This function overrides the `write` function of the base `response` class and writes the response
     * headers and body to the given output stream.
     *
     * @param os The output stream to write the response to.
     * @return A reference to the output stream.
     */
    std::ostream &write(std::ostream &os) const override
    {
      response::write(os) << str_body;
      return os;
    }

  private:
    json::json body;      // The JSON body of the response
    std::string str_body; // The body of the response
  };
} // namespace network
