#pragma once

#include "logging.h"
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio.hpp>
#include <boost/asio/system_executor.hpp>
#include <functional>

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
      signals.async_wait([this](boost::beast::error_code, int)
                         { close(); });

      resolver.async_resolve(host, service, [this](boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type results)
                             { on_resolve(ec, results); });
    }

    void set_on_connect_handler(std::function<void()> handler) { on_connect_handler = handler; }
    void set_on_error_handler(std::function<void(boost::beast::error_code)> handler) { on_connect_handler = handler; }
    void set_on_close_handler(std::function<void()> handler) { on_close_handler = handler; }

    template <class ReqBody, class ReqFields, class ResBody, class ResFields>
    void send(boost::beast::http::request<ReqBody, ReqFields> &&req, std::function<void(boost::beast::http::response<ResBody, ResFields> &&, boost::beast::error_code)> handler)
    {
      // Set a timeout on the operation
      boost::beast::get_lowest_layer(derived().get_stream()).expires_after(std::chrono::seconds(30));

      // Send the HTTP request to the remote host
      boost::beast::http::async_write(derived().get_stream(), req, [this, handler = std::move(handler)](boost::beast::error_code ec, std::size_t bytes_transferred)
                                      { on_write(handler, ec, bytes_transferred); });
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

    template <class ResBody, class ResFields>
    void on_write(std::function<void(boost::beast::http::response<ResBody, ResFields> &&, boost::beast::error_code)> handler, boost::beast::error_code ec, std::size_t)
    {
      if (ec)
      {
        LOG_ERR("on_write: " << ec.message());
        on_error_handler(ec);
        return;
      }

      auto res = new boost::beast::http::response<ResBody, ResFields>();

      // Receive the HTTP response
      boost::beast::http::async_read(derived().get_stream(), buffer, *res, [this, handler = std::move(handler), res](boost::beast::error_code ec, std::size_t bytes_transferred)
                                     { on_read(handler, res, ec, bytes_transferred); });
    }

    template <class ResBody, class ResFields>
    void on_read(std::function<void(boost::beast::http::response<ResBody, ResFields> &&, boost::beast::error_code)> handler, boost::beast::http::response<ResBody, ResFields> *res, boost::beast::error_code ec, std::size_t)
    {
      if (ec)
      {
        LOG_ERR("on_read: " << ec.message());
        on_error_handler(ec);
        return;
      }

      handler(*res, ec);
      delete res;
    }

  protected:
    boost::asio::strand<boost::asio::system_executor> strand;
    std::function<void()> on_connect_handler = []() {};
    std::function<void(boost::beast::error_code)> on_error_handler = [](boost::beast::error_code) {};
    std::function<void()> on_close_handler = []() {};

  private:
    boost::asio::signal_set signals;
    boost::asio::ip::tcp::resolver resolver;
    boost::beast::flat_buffer buffer;
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
        on_error_handler(ec);
        return;
      }

      on_connect_handler();
    }

    void close() override
    {
      stream.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both);

      on_close_handler();
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
        on_error_handler(ec);
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
        on_error_handler(ec);
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
        on_error_handler(ec);
        return;
      }

      on_connect_handler();
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
        on_error_handler(ec);
        return;
      }

      on_close_handler();
    }

  private:
    boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12}; // The SSL context is required, and holds certificates
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream;
  };
} // namespace network
