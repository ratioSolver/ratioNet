#pragma once

#include "json.h"
#include "memory.h"
#include <boost/asio.hpp>

namespace network
{
  enum method
  {
    GET,
    POST,
    PUT,
    DELETE
  };

  class request
  {
  public:
    request(boost::asio::ip::tcp::socket &socket, method m, std::string path, std::string version, std::map<std::string, std::string> headers) : socket(socket), m(m), path(path), version(version), headers(headers) {}
    virtual ~request() = default;

    boost::asio::ip::tcp::socket &socket;
    method m;
    std::string path, version;
    std::map<std::string, std::string> headers;
  };

  class json_request : public request
  {
  public:
    json_request(boost::asio::ip::tcp::socket &socket, method m, std::string path, std::string version, std::map<std::string, std::string> headers, json::json body) : request(socket, m, path, version, headers), body(std::move(body)) {}

    json::json body;
  };

  class response
  {
  public:
    response(boost::asio::ip::tcp::socket &socket, std::string version = "HTTP/1.1", int status_code = 200) : socket(socket), version(version), status_code(status_code), headers(headers) {}
    virtual ~response() = default;

    friend std::ostream &operator<<(std::ostream &os, const response &res)
    {
      os << res.version << " " << res.status_code << "\r\n";
      for (auto &header : res.headers)
        os << header.first << ": " << header.second << "\r\n";
      os << "\r\n";
      return os;
    }

    boost::asio::ip::tcp::socket &socket;
    std::string version;
    int status_code;
    std::map<std::string, std::string> headers;
  };

  using response_ptr = utils::u_ptr<response>;

  class json_response : public response
  {
  public:
    json_response(boost::asio::ip::tcp::socket &socket, std::string version = "HTTP/1.1", int status_code = 200, json::json body = json::json()) : response(socket, version, status_code), body(std::move(body)) {}

    friend std::ostream &operator<<(std::ostream &os, const json_response &res)
    {
      os << static_cast<const response &>(res);
      os << res.body;
      return os;
    }

    json::json body;
  };

  class server
  {
  public:
    server(short port);

    void add_route(method m, std::string path, std::function<response_ptr(request &)> callback)
    {
      switch (m)
      {
      case method::GET:
        get_routes[path] = callback;
        break;
      case method::POST:
        post_routes[path] = callback;
        break;
      case method::PUT:
        put_routes[path] = callback;
        break;
      case method::DELETE:
        delete_routes[path] = callback;
        break;
      }
    }

  private:
    void start_accept();

    request parse_request(boost::asio::ip::tcp::socket &socket);

  private:
    boost::asio::io_service io_service;
    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::socket socket;
    std::map<std::string, std::function<response_ptr(request &)>> get_routes, post_routes, put_routes, delete_routes;
  };
} // namespace network