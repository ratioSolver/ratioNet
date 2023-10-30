#pragma once

#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio.hpp>
#include <boost/asio/system_executor.hpp>
#include <functional>
#include <queue>

#ifdef VERBOSE_LOG
#include <iostream>

#ifdef WIN32
#define COLOR_NORMAL ""
#define COLOR_RED ""
#define COLOR_GREEN ""
#define COLOR_YELLOW ""
#else
#define COLOR_NORMAL "\033[0m"
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#endif

#define LOG_ERR(msg) std::cerr << COLOR_RED << __FILE__ << "(" << __LINE__ << "): " << msg << COLOR_NORMAL << std::endl
#define LOG_WARN(msg) std::clog << COLOR_YELLOW << __FILE__ << "(" << __LINE__ << "): " << msg << COLOR_NORMAL << std::endl
#define LOG_DEBUG(msg) std::clog << COLOR_GREEN << __FILE__ << "(" << __LINE__ << "): " << msg << COLOR_NORMAL << std::endl
#define LOG(msg) std::cout << COLOR_NORMAL << __FILE__ << "(" << __LINE__ << "): " << msg << COLOR_NORMAL << std::endl
#else
#define LOG_ERR(msg) \
  {                  \
  }
#define LOG_WARN(msg) \
  {                   \
  }
#define LOG_DEBUG(msg) \
  {                    \
  }
#define LOG(msg) \
  {              \
  }
#endif

namespace network
{
  class plain_ws_client;
  class ssl_ws_client;

  inline std::function<void()> default_on_connect_handler = []()
  { LOG("Connected!"); };
  inline std::function<void(boost::beast::error_code)> default_on_error_handler = []([[maybe_unused]] boost::beast::error_code ec)
  { LOG_ERR("Error: " << ec.message()); };
  inline std::function<void(const std::string &)> default_on_message_handler = []([[maybe_unused]] const std::string &message)
  { LOG("Received message: " << message); };
  inline std::function<void()> default_on_close_handler = []()
  { LOG("Closed!"); };

  template <class Derived>
  class ws_client
  {
    friend class plain_ws_client;
    friend class ssl_ws_client;

    Derived &derived() { return static_cast<Derived &>(*this); }

  public:
    ws_client(const std::string &host, const std::string &port, const std::string &path, boost::asio::strand<boost::asio::system_executor> strand, std::function<void()> on_connect_handler = default_on_connect_handler, std::function<void(const std::string &)> on_message_handler = default_on_message_handler, std::function<void(boost::beast::error_code)> on_error_handler = default_on_error_handler, std::function<void()> on_close_handler = default_on_close_handler) : host(host), port(port), path(path), strand(strand), signals(strand), resolver(strand), on_connect_handler(on_connect_handler), on_message_handler(on_message_handler), on_error_handler(on_error_handler), on_close_handler(on_close_handler)
    {
      signals.add(SIGINT);
      signals.add(SIGTERM);
#if defined(SIGQUIT)
      signals.add(SIGQUIT);
#endif
      signals.async_wait([this](boost::beast::error_code ec, [[maybe_unused]] int signo)
                         {
                            LOG_DEBUG("Received signal " << signo);
                            if (ec)
                            {
                              LOG_ERR("signals: " << ec.message());
                              return;
                            }
  
                            close(); });

      do_resolve();
    }

    void send(const std::string &&msg) { enqueue(std::make_shared<const std::string>(std::move(msg))); }

    void send(const std::shared_ptr<const std::string> &msg) { boost::asio::post(derived().get_stream().get_executor(), boost::beast::bind_front_handler(&ws_client::enqueue, this, msg)); }

    void close()
    { // Perform the SSL shutdown
      derived().get_stream().async_close(boost::beast::websocket::close_code::normal, boost::beast::bind_front_handler(&ws_client::on_close, this));
    }

  private:
    void do_resolve() { resolver.async_resolve(host, port, boost::beast::bind_front_handler(&ws_client::on_resolve, this)); }

    void on_resolve(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type results)
    {
      if (ec)
      {
        LOG_ERR("resolve: " << ec.message());
        on_error_handler(ec);
        return;
      }

      // Set a timeout on the operation
      boost::beast::get_lowest_layer(derived().get_stream()).expires_after(std::chrono::seconds(30));

      // Make the connection on the IP address we get from a lookup
      boost::beast::get_lowest_layer(derived().get_stream()).async_connect(results, boost::beast::bind_front_handler(&ws_client::on_connect, this));
    }

    virtual void on_connect(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type::endpoint_type ep) = 0;

  private:
    void on_handshake(boost::beast::error_code ec)
    {
      if (ec)
      {
        LOG_ERR("handshake: " << ec.message());
        on_error_handler(ec);
        return;
      }

      on_connect_handler();

      // Read a message into our buffer
      do_read();
    }

    void enqueue(const std::shared_ptr<const std::string> &msg)
    {
      send_queue.push(msg);

      if (send_queue.size() > 1)
        return; // already sending

      do_write();
    }

    void do_read() { derived().get_stream().async_read(buffer, boost::beast::bind_front_handler(&ws_client::on_read, this)); }
    void on_read(boost::beast::error_code ec, [[maybe_unused]] std::size_t bytes_transferred)
    {
      if (ec)
      {
        LOG_ERR("read: " << ec.message());
        on_error_handler(ec);
        return;
      }

      on_message_handler(boost::beast::buffers_to_string(buffer.data()));
    }

    void do_write() { derived().get_stream().async_write(boost::asio::buffer(*send_queue.front()), boost::asio::bind_executor(derived().get_stream().get_executor(), boost::beast::bind_front_handler(&ws_client::on_write, this))); }
    void on_write(boost::beast::error_code ec, [[maybe_unused]] std::size_t bytes_transferred)
    {
      if (ec)
      {
        LOG_ERR("write: " << ec.message());
        on_error_handler(ec);
        return;
      }

      send_queue.pop();

      if (!send_queue.empty())
        do_write();
    }

    void on_close(boost::beast::error_code ec)
    {
      if (ec)
      {
        LOG_ERR("close: " << ec.message());
        return;
      }

      on_close_handler();
    }

  protected:
    std::string host;
    const std::string port, path;
    boost::asio::strand<boost::asio::system_executor> strand;

  private:
    boost::asio::signal_set signals;
    boost::asio::ip::tcp::resolver resolver;
    boost::beast::flat_buffer buffer;

  protected:
    std::function<void()> on_connect_handler;
    std::function<void(const std::string &)> on_message_handler;
    std::function<void(boost::beast::error_code)> on_error_handler;
    std::function<void()> on_close_handler;

  private:
    std::queue<std::shared_ptr<const std::string>> send_queue;
  };

  class plain_ws_client : public ws_client<plain_ws_client>
  {
    friend class ws_client<plain_ws_client>;

  public:
    plain_ws_client(const std::string &host = "localhost", const std::string &port = "80", const std::string &path = "/", std::function<void()> on_connect_handler = default_on_connect_handler, std::function<void(const std::string &)> on_message_handler = default_on_message_handler, std::function<void(boost::beast::error_code)> on_error_handler = default_on_error_handler, std::function<void()> on_close_handler = default_on_close_handler) : ws_client(host, port, path, boost::asio::make_strand(boost::asio::system_executor()), on_connect_handler, on_message_handler, on_error_handler, on_close_handler), stream(strand) {}

  private:
    boost::beast::websocket::stream<boost::beast::tcp_stream> &get_stream() { return stream; }

    void on_connect(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type::endpoint_type ep)
    {
      if (ec)
      {
        LOG_ERR("connect: " << ec.message());
        return;
      }

      // Turn off the timeout on the tcp_stream, because
      // the websocket stream has its own timeout system.
      boost::beast::get_lowest_layer(stream).expires_never();

      // Set suggested timeout settings for the websocket
      stream.set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::client));

      // Set a decorator to change the User-Agent of the handshake
      stream.set_option(boost::beast::websocket::stream_base::decorator([](boost::beast::websocket::request_type &req)
                                                                        { req.set(boost::beast::http::field::user_agent, "ratioNet ws_client"); }));

      // Update the host string. This will provide the value of the Host HTTP header during the WebSocket handshake.
      // See https://tools.ietf.org/html/rfc7230#section-5.4
      host += ':' + std::to_string(ep.port());

      // Perform the websocket handshake
      stream.async_handshake(host, path, boost::beast::bind_front_handler(&ws_client::on_handshake, this));
    }

  private:
    boost::beast::websocket::stream<boost::beast::tcp_stream> stream;
  };

  class ssl_ws_client : public ws_client<ssl_ws_client>
  {
    friend class ws_client<ssl_ws_client>;

  public:
    ssl_ws_client(const std::string &host = "localhost", const std::string &port = "443", const std::string &path = "/", std::function<void()> on_connect_handler = default_on_connect_handler, std::function<void(const std::string &)> on_message_handler = default_on_message_handler, std::function<void(boost::beast::error_code)> on_error_handler = default_on_error_handler, std::function<void()> on_close_handler = default_on_close_handler) : ws_client(host, port, path, boost::asio::make_strand(boost::asio::system_executor()), on_connect_handler, on_message_handler, on_error_handler, on_close_handler), stream(strand, ctx) {}

  private:
    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>> &get_stream() { return stream; }

    void on_connect(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type::endpoint_type ep)
    {
      if (ec)
      {
        LOG_ERR("connect: " << ec.message());
        return;
      }

      // Set suggested timeout settings for the websocket
      boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));

      // Set SNI Hostname (many hosts need this to handshake successfully)
      if (!SSL_set_tlsext_host_name(stream.next_layer().native_handle(), host.c_str()))
      {
        boost::beast::error_code ec{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()};
        LOG_ERR("SSL_set_tlsext_host_name: " << ec.message());
        on_error_handler(ec);
        return;
      }

      // Update the host string. This will provide the value of the Host HTTP header during the WebSocket handshake.
      // See https://tools.ietf.org/html/rfc7230#section-5.4
      host += ':' + std::to_string(ep.port());

      // Perform the SSL handshake
      stream.next_layer().async_handshake(boost::asio::ssl::stream_base::client, boost::beast::bind_front_handler(&ssl_ws_client::on_ssl_handshake, this));
    }

    void on_ssl_handshake(boost::beast::error_code ec)
    {
      if (ec)
      {
        LOG_ERR("ssl_handshake: " << ec.message());
        on_error_handler(ec);
        return;
      }

      // Turn off the timeout on the tcp_stream, because
      // the websocket stream has its own timeout system.
      boost::beast::get_lowest_layer(stream).expires_never();

      // Set suggested timeout settings for the websocket
      stream.set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::client));

      // Set a decorator to change the User-Agent of the handshake
      stream.set_option(boost::beast::websocket::stream_base::decorator([](boost::beast::websocket::request_type &req)
                                                                        { req.set(boost::beast::http::field::user_agent, "ratioNet ws_client"); }));

      // Perform the websocket handshake
      stream.async_handshake(host, path, boost::beast::bind_front_handler(&ws_client::on_handshake, this));
    }

  private:
    boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12_client};
    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>> stream;
  };
} // namespace network
