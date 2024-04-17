#pragma once

#include <boost/asio.hpp>
#include "json.hpp"

namespace network
{
  enum verb
  {
    GET,
    POST,
    PUT,
    DELETE
  };

  inline std::string to_string(verb v)
  {
    switch (v)
    {
    case GET:
      return "GET";
    case POST:
      return "POST";
    case PUT:
      return "PUT";
    case DELETE:
      return "DELETE";
    }
    return {};
  }

  class server;

  class session : public std::enable_shared_from_this<session>
  {
  public:
    session(server &srv, boost::asio::ip::tcp::socket socket);
    ~session();

    void start();

  private:
    void on_read(const boost::system::error_code &ec, std::size_t bytes_transferred);
    void on_body(const boost::system::error_code &ec, std::size_t bytes_transferred);

  private:
    server &srv;
    boost::asio::ip::tcp::socket socket;
    boost::asio::streambuf buffer;
    verb v;
    std::string target, version;
    std::map<std::string, std::string> headers;
  };

  class request
  {
  public:
    request(std::shared_ptr<session> s, verb v, std::string &&trgt, std::string &&ver, std::map<std::string, std::string> &&hdrs) : s(s), v(v), target(trgt), version(ver), headers(hdrs) {}
    ~request() = default;

    verb get_verb() const { return v; }
    const std::string &get_target() const { return target; }
    const std::string &get_version() const { return version; }
    const std::map<std::string, std::string> &get_headers() const { return headers; }

    friend std::ostream &operator<<(std::ostream &os, const request &req)
    {
      os << to_string(req.v) << ' ' << req.target << " " << req.version << std::endl;
      for (const auto &header : req.headers)
        os << header.first << ": " << header.second << std::endl;
      return os;
    }

  protected:
    std::shared_ptr<session> s;
    verb v;
    std::string target, version;
    std::map<std::string, std::string> headers;
  };

  class string_request : public request
  {
  public:
    string_request(std::shared_ptr<session> s, verb v, std::string &&trgt, std::string &&ver, std::map<std::string, std::string> &&hdrs, std::string &&b) : request(s, v, std::move(trgt), std::move(ver), std::move(hdrs)), body(std::move(b)) {}
    ~string_request() = default;

    const std::string &get_body() const { return body; }

    friend std::ostream &operator<<(std::ostream &os, const string_request &req)
    {
      os << static_cast<const request &>(req);
      os << req.body;
      return os;
    }

  private:
    std::string body;
  };

  class json_request : public request
  {
  public:
    json_request(std::shared_ptr<session> s, verb v, std::string &&trgt, std::string &&ver, std::map<std::string, std::string> &&hdrs, json::json &&b) : request(s, v, std::move(trgt), std::move(ver), std::move(hdrs)), body(std::move(b)) {}
    ~json_request() = default;

    const json::json &get_body() const { return body; }

    friend std::ostream &operator<<(std::ostream &os, const json_request &req)
    {
      os << static_cast<const request &>(req);
      os << req.body;
      return os;
    }

  private:
    json::json body;
  };

  class server
  {
    friend class session;

  public:
    server(const std::string &address = "0.0.0.0", unsigned short port = 8080, std::size_t concurrency_hint = std::thread::hardware_concurrency());

    /**
     * @brief Start the server.
     */
    void start();

  private:
    void do_accept();
    void on_accept(const boost::system::error_code &ec, boost::asio::ip::tcp::socket socket);

    void handle_request(request &&req);

  private:
    boost::asio::io_context io_ctx;          // The io_context is required for all I/O
    std::vector<std::thread> threads;        // The thread pool
    boost::asio::ip::tcp::endpoint endpoint; // The endpoint for the server
    boost::asio::ip::tcp::acceptor acceptor; // The acceptor for the server
  };
} // namespace network
