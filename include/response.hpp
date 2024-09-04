#pragma once

#include <asio.hpp>
#include <fstream>
#include "status_code.hpp"
#include "mime_types.hpp"
#include "json.hpp"

namespace network
{
  class client;

  /**
   * @brief Represents an HTTP response.
   */
  class response
  {
    friend class client;

  public:
    /**
     * @brief Constructs a response object.
     *
     * @param code The status code of the response.
     * @param hdrs The headers of the response.
     * @param ver The HTTP version of the response.
     */
    response(status_code code = status_code::ok, std::map<std::string, std::string> &&hdrs = {}, std::string &&ver = "HTTP/1.1") : code(code), headers(hdrs), version(ver) {}

    /**
     * @brief Gets the status code of the response.
     *
     * @return The status code.
     */
    status_code get_status_code() const { return code; }

    /**
     * @brief Gets the headers of the response.
     *
     * @return The headers.
     */
    const std::map<std::string, std::string> &get_headers() const { return headers; }

    /**
     * @brief Gets the HTTP version of the response.
     *
     * @return The HTTP version.
     */
    const std::string &get_version() const { return version; }

    /**
     * @brief Writes the response to an output stream.
     *
     * @param os The output stream to write to.
     * @return A reference to the output stream after writing.
     */
    friend std::ostream &operator<<(std::ostream &os, const response &res) { return res.write(os); }

    /**
     * @brief Gets the buffer containing the response.
     *
     * @return The buffer.
     */
    asio::streambuf &get_buffer()
    {
      std::ostream os(&buffer);
      write(os); // Write the response to the buffer
      return buffer;
    }

    /**
     * @brief Parses the response.
     *
     * This function is responsible for parsing the response.
     * It performs the necessary operations to extract relevant information from the response.
     */
    void parse()
    {
      std::istream is(&buffer);

      std::string c_version;
      while (is.peek() != ' ')
        c_version += is.get();
      version = std::move(c_version);
      is.get(); // consume ' '
      std::string c_code;
      while (is.peek() != ' ' && is.peek() != '\r')
        c_code += is.get();
      code = static_cast<status_code>(std::stoi(c_code));
      if (is.peek() == ' ')
      {
        is.get(); // consume ' '
        std::string c_reason;
        while (is.peek() != '\r')
          c_reason += is.get();
      }
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

        // convert header to lowercase
        std::transform(header.begin(), header.end(), header.begin(), [](unsigned char c)
                       { return std::tolower(c); });

        // add header to the map
        headers.emplace(std::move(header), std::move(value));
      }
      is.get(); // consume '\r'
      is.get(); // consume '\n'
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
    std::map<std::string, std::string> headers; // The headers of the response

  private:
    std::string version;    // The HTTP version of the response
    asio::streambuf buffer; // The buffer containing the response
  };

  /**
   * @brief A class representing a string response.
   *
   * This class inherits from the base class response and provides functionality to handle string responses.
   */
  class string_response : public response
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
    string_response(std::string &&b, status_code code = status_code::ok, std::map<std::string, std::string> &&hdrs = {}, std::string &&ver = "HTTP/1.1") : response(code, std::move(hdrs), std::move(ver)), body(std::move(b))
    {
      headers["content-type"] = "text/plain";
      headers["content-length"] = std::to_string(body.size());
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
  class html_response : public response
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
    html_response(std::string &&b, status_code code = status_code::ok, std::map<std::string, std::string> &&hdrs = {}, std::string &&ver = "HTTP/1.1") : response(code, std::move(hdrs), std::move(ver)), body(std::move(b))
    {
      headers["content-type"] = "text/html";
      headers["content-length"] = std::to_string(body.size());
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
  class file_response : public response
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
    file_response(std::string &&f, status_code code = status_code::ok, std::map<std::string, std::string> &&hdrs = {}, std::string &&ver = "HTTP/1.1") : response(code, std::move(hdrs), std::move(ver)), file(std::move(f))
    {
      std::ifstream fs(file, std::ios::binary);
      if (!fs)
        throw std::invalid_argument("Could not open file: " + file);

      fs.seekg(0, std::ios::end);
      headers["content-length"] = std::to_string(fs.tellg());

      auto ext = file.substr(file.find_last_of('.') + 1);
      headers["content-type"] = network::mime_types.at(ext);
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
  class json_response : public response
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
    json_response(json::json &&b, status_code code = status_code::ok, std::map<std::string, std::string> &&hdrs = {}, std::string &&ver = "HTTP/1.1") : response(code, std::move(hdrs), std::move(ver)), body(std::move(b)), str_body(body.dump())
    {
      headers["content-type"] = "application/json";
      headers["content-length"] = std::to_string(str_body.size());
    }
    /**
     * @brief Constructs a `json_response` object with the given JSON body, status code, headers, and version.
     *
     * @param b The JSON body of the response.
     * @param code The status code of the response. Default is `status_code::ok`.
     * @param hdrs The headers of the response. Default is an empty map.
     * @param ver The version of the HTTP protocol. Default is "HTTP/1.1".
     */
    json_response(const json::json &b, status_code code = status_code::ok, std::map<std::string, std::string> &&hdrs = {}, std::string &&ver = "HTTP/1.1") : response(code, std::move(hdrs), std::move(ver)), body(b), str_body(body.dump())
    {
      headers["content-type"] = "application/json";
      headers["content-length"] = std::to_string(str_body.size());
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
