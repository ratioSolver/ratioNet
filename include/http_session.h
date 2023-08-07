#pragma once

#include "websocket_session.h"

namespace network
{
  /**
   * @brief Base class for HTTP sessions.
   *
   * @tparam Derived The derived class.
   */
  template <class Derived>
  class http_session
  {
    Derived &derived() { return static_cast<Derived &>(*this); }

  public:
    http_session(boost::beast::flat_buffer buffer) : buffer(std::move(buffer)) {}

  private:
    void do_read()
    {
    }

  private:
    void on_read(boost::system::error_code ec, [[maybe_unused]] size_t bytes_transferred)
    {
    }

    void on_write(boost::system::error_code ec, [[maybe_unused]] size_t bytes_transferred)
    {
    }

  private:
    boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser;

  protected:
    boost::beast::flat_buffer buffer;
  };
} // namespace network
