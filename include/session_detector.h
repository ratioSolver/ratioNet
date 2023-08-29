#pragma once

#include <boost/beast.hpp>
#include <boost/asio/ssl.hpp>

namespace network
{
  class session_detector
  {
  public:
    session_detector(boost::asio::ip::tcp::socket &&socket, boost::asio::ssl::context &ctx);

  private:
    void on_detect(boost::beast::error_code ec, bool result);

  private:
    boost::beast::tcp_stream stream;
    boost::asio::ssl::context &ctx;
    boost::beast::flat_buffer buffer;
  };
} // namespace network
