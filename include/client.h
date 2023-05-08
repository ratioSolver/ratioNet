#pragma once

#include "request.h"
#include "response.h"
#include <boost/asio.hpp>

namespace network
{
  class client
  {
  public:
    client(std::string host = "localhost", std::string port = "8080");

    response_ptr call(const request &req);

  private:
    boost::asio::io_service io_service;
    boost::asio::ip::tcp::resolver::results_type endpoints;
    boost::asio::ip::tcp::socket socket;
  };
} // namespace network
