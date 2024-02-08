#pragma once

#include <functional>
#include <boost/beast.hpp>

namespace network
{
  inline std::function<void()> default_on_connect_handler = []() {};
  inline std::function<void(boost::beast::error_code)> default_on_error_handler = []([[maybe_unused]] boost::beast::error_code ec) {};
  inline std::function<void(const std::string &)> default_on_message_handler = []([[maybe_unused]] const std::string &message) {};
  inline std::function<void()> default_on_close_handler = []() {};

  class base_ws_client
  {
  };
} // namespace network
