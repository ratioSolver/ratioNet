#pragma once

#include <boost/asio.hpp>
#include <boost/beast.hpp>

namespace network
{
  using response = boost::beast::http::response<boost::beast::http::dynamic_body>;

  class client
  {
  public:
    client(const std::string &host, const std::string &service = "8080");

    response get(const std::string &target, const std::unordered_map<std::string, std::string> &headers = {});
    response post(const std::string &target, const std::string &body, const std::unordered_map<std::string, std::string> &headers = {});
    response put(const std::string &target, const std::string &body, const std::unordered_map<std::string, std::string> &headers = {});
    response del(const std::string &target, const std::unordered_map<std::string, std::string> &headers = {});

    void stop();

  private:
    std::string host;
    boost::asio::io_context io_context;
    boost::asio::signal_set signals;
    boost::asio::ip::tcp::socket socket;
    const boost::asio::ip::basic_resolver_results<boost::asio::ip::tcp> results;
  };
} // namespace network
