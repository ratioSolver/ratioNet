#pragma once

#include <functional>
#include <queue>
#include <boost/beast.hpp>
#include <boost/asio.hpp>
#ifdef USE_SSL
#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>
#endif

namespace network
{
  class ws_client;
#ifdef USE_SSL
  class wss_client;
#endif

  inline std::function<void()> default_on_connect_handler = []() {};
  inline std::function<void(const std::string &)> default_on_message_handler = []([[maybe_unused]] const std::string &message) {};
  inline std::function<void(boost::beast::error_code)> default_on_error_handler = []([[maybe_unused]] boost::beast::error_code ec) {};
  inline std::function<void()> default_on_close_handler = []() {};

  template <class Derived>
  class base_ws_client
  {
    friend class ws_client;
#ifdef USE_SSL
    friend class wss_client;
#endif

    Derived &derived() { return static_cast<Derived &>(*this); }

  public:
    base_ws_client(const std::string &host = SERVER_ADDRESS, const std::string &port = SERVER_PORT, const std::string &path = "/ws", std::function<void()> on_connect_handler = default_on_connect_handler, std::function<void(const std::string &)> on_message_handler = default_on_message_handler, std::function<void(boost::beast::error_code)> on_error_handler = default_on_error_handler, std::function<void()> on_close_handler = default_on_close_handler) : host(host), port(port), path(path), on_connect_handler(on_connect_handler), on_message_handler(on_message_handler), on_error_handler(on_error_handler), on_close_handler(on_close_handler)
    {
#ifdef SIGQUIT
      signals.add(SIGQUIT);
#endif
      signals.async_wait([this](boost::beast::error_code, int)
                         { close(); });
    }
    virtual ~base_ws_client() = default;

    void send(const std::string &&msg) { enqueue(std::make_shared<const std::string>(std::move(msg))); }

    void send(const std::shared_ptr<const std::string> &msg) { boost::asio::post(derived().get_stream().get_executor(), boost::beast::bind_front_handler(&base_ws_client::enqueue, this, msg)); }

    void close() { derived().get_stream().async_close(boost::beast::websocket::close_code::normal, boost::beast::bind_front_handler(&base_ws_client::on_close, this)); }

  private:
    void do_resolve() { resolver.async_resolve(host, port, boost::beast::bind_front_handler(&base_ws_client::on_resolve, this)); }

    void on_resolve(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type results)
    {
      if (ec)
        return on_error_handler(ec);

      // Set a timeout on the operation
      boost::beast::get_lowest_layer(derived().get_stream()).expires_after(std::chrono::seconds(30));

      // Make the connection on the IP address we get from a lookup
      boost::beast::get_lowest_layer(derived().get_stream()).async_connect(results, boost::beast::bind_front_handler(&base_ws_client::on_connect, this));
    }

    virtual void on_connect(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type::endpoint_type ep) = 0;

    void on_handshake(boost::beast::error_code ec)
    {
      if (ec)
        return on_error_handler(ec);

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

    void do_read() { derived().get_stream().async_read(buffer, boost::beast::bind_front_handler(&base_ws_client::on_read, this)); }
    void on_read(boost::beast::error_code ec, [[maybe_unused]] std::size_t bytes_transferred)
    {
      if (ec)
        return on_error_handler(ec);

      on_message_handler(boost::beast::buffers_to_string(buffer.data()));
    }

    void do_write() { derived().get_stream().async_write(boost::asio::buffer(*send_queue.front()), boost::asio::bind_executor(derived().get_stream().get_executor(), boost::beast::bind_front_handler(&base_ws_client::on_write, this))); }
    void on_write(boost::beast::error_code ec, [[maybe_unused]] std::size_t bytes_transferred)
    {
      if (ec)
        return on_error_handler(ec);

      send_queue.pop();

      if (!send_queue.empty())
        do_write();
    }

    void on_close(boost::beast::error_code ec)
    {
      if (ec)
        return on_error_handler(ec);

      on_close_handler();
    }

  protected:
    std::string host;
    std::string port;
    std::string path;
    boost::asio::strand<boost::asio::system_executor> strand{boost::asio::system_executor()};
    boost::asio::signal_set signals{strand, SIGINT, SIGTERM};
    boost::asio::ip::tcp::resolver resolver{strand};
    boost::beast::flat_buffer buffer;
    std::function<void()> on_connect_handler;
    std::function<void(boost::beast::error_code)> on_error_handler;
    std::function<void(const std::string &)> on_message_handler;
    std::function<void()> on_close_handler;

  private:
    std::queue<std::shared_ptr<const std::string>> send_queue;
  };

  class ws_client : public base_ws_client<ws_client>
  {
  public:
    ws_client(const std::string &host = SERVER_ADDRESS, const std::string &port = SERVER_PORT, const std::string &path = "/ws", std::function<void()> on_connect_handler = default_on_connect_handler, std::function<void(const std::string &)> on_message_handler = default_on_message_handler, std::function<void(boost::beast::error_code)> on_error_handler = default_on_error_handler, std::function<void()> on_close_handler = default_on_close_handler) : base_ws_client(host, port, path, on_connect_handler, on_message_handler, on_error_handler, on_close_handler) { do_resolve(); }

    boost::beast::websocket::stream<boost::beast::tcp_stream> &get_stream() { return stream; }

  private:
    void on_connect(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type::endpoint_type ep) override
    {
      if (ec)
        return on_error_handler(ec);

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
      stream.async_handshake(host, path, boost::beast::bind_front_handler(&base_ws_client::on_handshake, this));
    }

  private:
    boost::beast::websocket::stream<boost::beast::tcp_stream> stream{strand};
  };

#ifdef USE_SSL
  class wss_client : public base_ws_client<wss_client>
  {
  public:
    wss_client(const std::string &host = SERVER_ADDRESS, const std::string &port = SERVER_PORT, const std::string &path = "/wss", std::function<void()> on_connect_handler = default_on_connect_handler, std::function<void(const std::string &)> on_message_handler = default_on_message_handler, std::function<void(boost::beast::error_code)> on_error_handler = default_on_error_handler, std::function<void()> on_close_handler = default_on_close_handler) : base_ws_client(host, port, path, on_connect_handler, on_message_handler, on_error_handler, on_close_handler) { do_resolve(); }

    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>> &get_stream() { return stream; }

  private:
    void on_connect(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type::endpoint_type ep) override
    {
      if (ec)
        return on_error_handler(ec);

      // Set suggested timeout settings for the websocket
      boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));

      // Set SNI Hostname (many hosts need this to handshake successfully)
      if (!SSL_set_tlsext_host_name(stream.next_layer().native_handle(), host.c_str()))
      {
        boost::beast::error_code ec{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()};
        on_error_handler(ec);
        return;
      }

      // Update the host string. This will provide the value of the Host HTTP header during the WebSocket handshake.
      // See https://tools.ietf.org/html/rfc7230#section-5.4
      host += ':' + std::to_string(ep.port());

      // Perform the SSL handshake
      stream.next_layer().async_handshake(boost::asio::ssl::stream_base::client, boost::beast::bind_front_handler(&wss_client::on_ssl_handshake, this));
    }

    void on_ssl_handshake(boost::beast::error_code ec)
    {
      if (ec)
        return on_error_handler(ec);

      // Turn off the timeout on the tcp_stream, because
      // the websocket stream has its own timeout system.
      boost::beast::get_lowest_layer(stream).expires_never();

      // Set suggested timeout settings for the websocket
      stream.set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::client));

      // Set a decorator to change the User-Agent of the handshake
      stream.set_option(boost::beast::websocket::stream_base::decorator([](boost::beast::websocket::request_type &req)
                                                                        { req.set(boost::beast::http::field::user_agent, "ratioNet wss_client"); }));

      // Perform the websocket handshake
      stream.async_handshake(host, path, boost::beast::bind_front_handler(&base_ws_client::on_handshake, this));
    }

  private:
    boost::asio::ssl::context ssl_ctx{boost::asio::ssl::context::TLS_VERSION};
    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>> stream{strand, ssl_ctx};
  };
#endif
} // namespace network
