#pragma once

#include "websocket_session.h"

namespace network
{
  /**
   * @brief Base class for HTTP sessions.
   *
   */
  class http_session
  {
  public:
    http_session(boost::beast::flat_buffer buffer) : buffer(std::move(buffer)) {}
    virtual ~http_session() = default;

    void run();

  private:
    void on_read(boost::system::error_code ec, size_t bytes_transferred);
    void on_write(boost::system::error_code ec, size_t bytes_transferred, bool close);

  private:
    boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser;

  protected:
    boost::beast::flat_buffer buffer;
  };
} // namespace network
