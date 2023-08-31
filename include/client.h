#pragma once

#include "logging.h"
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio.hpp>
#include <boost/asio/system_executor.hpp>

namespace network
{
  template <class Derived>
  class client
  {
    Derived &derived() { return static_cast<Derived &>(*this); }

  public:
    client(boost::asio::strand<boost::asio::system_executor> strand, const std::string &host, const std::string &service) : strand(strand), signals(strand), resolver(strand)
    {
      signals.add(SIGINT);
      signals.add(SIGTERM);
#if defined(SIGQUIT)
      signals.add(SIGQUIT);
#endif
      signals.async_wait([this](boost::system::error_code, int)
                         { close(); });

      resolver.async_resolve(host, service, [this](boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type results)
                             { on_resolve(ec, results); });
    }

    virtual void close() = 0;

  private:
    void on_resolve(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type results)
    {
      if (ec)
      {
        LOG_ERR("on_resolve: " << ec.message());
        return;
      }

      // Set a timeout on the operation
      boost::beast::get_lowest_layer(derived().get_stream()).expires_after(std::chrono::seconds(30));

      // Make the connection on the IP address we get from a lookup
      boost::beast::get_lowest_layer(derived().get_stream()).async_connect(results, [this](boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type::endpoint_type ep)
                                                                           { on_connect(ec, ep); });
    }

    virtual void on_connect(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type::endpoint_type) = 0;

  protected:
    boost::asio::strand<boost::asio::system_executor> strand;

  private:
    boost::asio::signal_set signals;
    boost::asio::ip::tcp::resolver resolver;
  };

  class plain_client : public client<plain_client>
  {
    friend class client<plain_client>;

  public:
    plain_client(const std::string &host, const std::string &service = "80") : client(boost::asio::make_strand(boost::asio::system_executor()), host, service), stream(strand) {}

  private:
    boost::beast::tcp_stream &get_stream() { return stream; }

    void on_connect(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type::endpoint_type) override
    {
      if (ec)
      {
        LOG_ERR("on_connect: " << ec.message());
        return;
      }
    }

    void close() override
    {
      stream.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both);
    }

  private:
    boost::beast::tcp_stream stream;
  };

  class ssl_client : public client<ssl_client>
  {
    friend class client<ssl_client>;

  public:
    ssl_client(const std::string &host, const std::string &service = "443") : client(boost::asio::make_strand(boost::asio::system_executor()), host, service), stream(strand, ctx)
    {
      // Set SNI Hostname (many hosts need this to handshake successfully)
      if (!SSL_set_tlsext_host_name(stream.native_handle(), host.c_str()))
      {
        boost::beast::error_code ec{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()};
        LOG_ERR("SSL_set_tlsext_host_name: " << ec.message());
        return;
      }
    }

  private:
    boost::beast::ssl_stream<boost::beast::tcp_stream> &get_stream() { return stream; }

    void on_connect(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type::endpoint_type) override
    {
      if (ec)
      {
        LOG_ERR("on_connect: " << ec.message());
        return;
      }

      // Set a timeout on the operation
      boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));

      // Perform the SSL handshake
      stream.async_handshake(boost::asio::ssl::stream_base::client, [this](boost::beast::error_code ec)
                             { on_handshake(ec); });
    }

    void on_handshake(boost::beast::error_code ec)
    {
      if (ec)
      {
        LOG_ERR("on_handshake: " << ec.message());
        return;
      }
    }

    void close() override
    {
      // Set a timeout on the operation
      boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));

      // Perform the SSL shutdown
      stream.async_shutdown([this](boost::beast::error_code ec)
                            { on_shutdown(ec); });
    }

    void on_shutdown(boost::beast::error_code ec)
    {
      if (ec == boost::asio::error::eof)
      {
        // Rationale:
        // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
        ec = {};
      }
      if (ec)
      {
        LOG_ERR("on_shutdown: " << ec.message());
        return;
      }
    }

  private:
    boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12}; // The SSL context is required, and holds certificates
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream;
  };
} // namespace network
