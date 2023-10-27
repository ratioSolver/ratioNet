#pragma once

#include "logging.h"
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio.hpp>
#include <boost/asio/system_executor.hpp>
#include <functional>
#include <queue>

namespace network
{
  template <class Derived>
  class client;
  class plain_client;
  class ssl_client;

  class client_request

  {
    friend class client<plain_client>;
    friend class plain_client;
    friend class client<ssl_client>;
    friend class ssl_client;

  public:
    virtual ~client_request() = default;

  private:
    virtual void handle_request() = 0;
  };

  inline std::function<void()> default_on_connect_handler = []()
  { LOG("Connected!"); };
  inline std::function<void(boost::beast::error_code)> default_on_error_handler = []([[maybe_unused]] boost::beast::error_code ec)
  { LOG_ERR("on_error: " << ec.message()); };
  inline std::function<void()> default_on_close_handler = []()
  { LOG("Closed!"); };

  template <class Derived>
  class client
  {
    friend class client_request;

    Derived &derived() { return static_cast<Derived &>(*this); }

  public:
    client(const std::string &host, const std::string &port, boost::asio::strand<boost::asio::system_executor> strand, std::function<void()> on_connect_handler = default_on_connect_handler, std::function<void(boost::beast::error_code)> on_error_handler = default_on_error_handler, std::function<void()> on_close_handler = default_on_close_handler) : host(host), port(port), strand(strand), signals(strand), resolver(strand), on_connect_handler(on_connect_handler), on_error_handler(on_error_handler), on_close_handler(on_close_handler)
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
    }

    virtual void close() = 0;

    template <class Body>
    void get(const std::string &target, const std::function<void(const boost::beast::http::response<Body> &, boost::beast::error_code)> &handler) { get(target, {}, handler); }

    template <class Body>
    void get(const std::string &target, const std::unordered_map<boost::beast::http::field, std::string> &fields, const std::function<void(const boost::beast::http::response<Body> &, boost::beast::error_code)> &handler)
    {
      auto req = std::make_unique<boost::beast::http::request<boost::beast::http::empty_body>>(boost::beast::http::verb::get, target, 11);
      req->set(boost::beast::http::field::host, host);
      req->set(boost::beast::http::field::user_agent, "ratioNet");
      for (auto &field : fields)
        req->set(field.first, field.second);
      send(std::move(req), handler);
    }

    template <class Body>
    void post(const std::string &target, const std::string &body, const std::function<void(const boost::beast::http::response<Body> &, boost::beast::error_code)> &handler) { post(target, body, {}, handler); }

    template <class Body>
    void post(const std::string &target, const std::string &body, const std::unordered_map<boost::beast::http::field, std::string> &fields, const std::function<void(const boost::beast::http::response<Body> &, boost::beast::error_code)> &handler)
    {
      auto req = std::make_unique<boost::beast::http::request<boost::beast::http::string_body>>(boost::beast::http::verb::get, target, 11);
      req->set(boost::beast::http::field::host, host);
      req->set(boost::beast::http::field::user_agent, "ratioNet");
      for (auto &field : fields)
        req->set(field.first, field.second);
      req->body() = body;
      send(std::move(req), handler);
    }

    template <class Body>
    void put(const std::string &target, const std::string &body, const std::function<void(const boost::beast::http::response<Body> &, boost::beast::error_code)> &handler) { put(target, body, {}, handler); }

    template <class Body>
    void put(const std::string &target, const std::string &body, const std::unordered_map<boost::beast::http::field, std::string> &fields, const std::function<void(const boost::beast::http::response<Body> &, boost::beast::error_code)> &handler)
    {
      auto req = std::make_unique<boost::beast::http::request<boost::beast::http::string_body>>(boost::beast::http::verb::put, target, 11);
      req->set(boost::beast::http::field::host, host);
      req->set(boost::beast::http::field::user_agent, "ratioNet");
      for (auto &field : fields)
        req->set(field.first, field.second);
      req->body() = body;
      send(std::move(req), handler);
    }

    template <class Body>
    void patch(const std::string &target, const std::string &body, const std::function<void(const boost::beast::http::response<Body> &, boost::beast::error_code)> &handler) { patch(target, body, {}, handler); }

    template <class Body>
    void patch(const std::string &target, const std::string &body, const std::unordered_map<boost::beast::http::field, std::string> &fields, const std::function<void(const boost::beast::http::response<Body> &, boost::beast::error_code)> &handler)
    {
      auto req = std::make_unique<boost::beast::http::request<boost::beast::http::string_body>>(boost::beast::http::verb::put, target, 11);
      req->set(boost::beast::http::field::host, host);
      req->set(boost::beast::http::field::user_agent, "ratioNet");
      for (auto &field : fields)
        req->set(field.first, field.second);
      req->body() = body;
      send(std::move(req), handler);
    }

    template <class Body>
    void del(const std::string &target, const std::function<void(const boost::beast::http::response<Body> &, boost::beast::error_code)> &handler) { del(target, {}, handler); }

    template <class Body>
    void del(const std::string &target, const std::unordered_map<boost::beast::http::field, std::string> &fields, const std::function<void(const boost::beast::http::response<Body> &, boost::beast::error_code)> &handler)
    {
      auto req = std::make_unique<boost::beast::http::request<boost::beast::http::empty_body>>(boost::beast::http::verb::get, target, 11);
      req->set(boost::beast::http::field::host, host);
      req->set(boost::beast::http::field::user_agent, "ratioNet");
      for (auto &field : fields)
        req->set(field.first, field.second);
      send(std::move(req), handler);
    }

    template <class ReqBody, class ResBody>
    void send(std::unique_ptr<boost::beast::http::request<ReqBody>> req, const std::function<void(const boost::beast::http::response<ResBody> &, boost::beast::error_code)> &handler)
    {
      req->prepare_payload();

      boost::asio::post(strand, [this, req = std::move(req), handler]() mutable
                        { enqueue(std::move(req), handler); });
    }

  protected:
    void do_resolve() { resolver.async_resolve(host, port, boost::beast::bind_front_handler(&client::on_resolve, this)); }

  private:
    template <class ReqBody, class ResBody>
    void enqueue(std::unique_ptr<boost::beast::http::request<ReqBody>> req, const std::function<void(const boost::beast::http::response<ResBody> &, boost::beast::error_code)> &handler)
    {
      requests.push(std::make_shared<client_request_impl<Derived, ReqBody, ResBody>>(derived(), std::move(req), handler));

      if (requests.size() == 1) // If we have no work, make this call again..
        requests.front()->handle_request();
    }

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
      boost::beast::get_lowest_layer(derived().get_stream()).async_connect(results, boost::beast::bind_front_handler(&client::on_connect, this));
    }

    virtual void on_connect(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type::endpoint_type) = 0;

    template <class Session, class ReqBody, class ResBody>
    class client_request_impl : public client_request, public std::enable_shared_from_this<client_request_impl<Session, ReqBody, ResBody>>
    {
    public:
      client_request_impl(Session &session, std::unique_ptr<boost::beast::http::request<ReqBody>> req, const std::function<void(const boost::beast::http::response<ResBody> &, boost::beast::error_code)> &handler) : session(session), req(std::move(req)), handler(handler) {}

    private:
      void handle_request() override
      {
        // Set a timeout on the operation
        boost::beast::get_lowest_layer(session.get_stream()).expires_after(std::chrono::seconds(30));

        // Send the HTTP request to the remote host
        boost::beast::http::async_write(session.get_stream(), *req, boost::beast::bind_front_handler(&client_request_impl::on_write, this->shared_from_this()));
      }

      void on_write(boost::beast::error_code ec, std::size_t)
      {
        if (ec)
        {
          LOG_ERR("on_write: " << ec.message());
          handler(res, ec);
          return;
        }

        // Receive the HTTP response
        boost::beast::http::async_read(session.get_stream(), session.buffer, res, boost::asio::bind_executor(session.strand, boost::beast::bind_front_handler(&client_request_impl::on_read, this->shared_from_this())));
      }

      void on_read(boost::beast::error_code ec, std::size_t)
      {
        if (ec == boost::beast::http::error::end_of_stream)
        {
          session.do_resolve();
          return;
        }
        else if (ec)
        {
          LOG_ERR("on_read: " << ec.message());
          handler(res, ec);
          return;
        }

        handler(res, ec);

        session.requests.pop();
        if (!session.requests.empty()) // If we still have work to do, make this call again..
          session.requests.front()->handle_request();

        if (res.need_eof()) // This means we should close the connection, usually because the response indicated the "Connection: close" semantic.
          session.close();
      }

    private:
      Session &session;
      std::unique_ptr<boost::beast::http::request<ReqBody>> req;
      boost::beast::http::response<ResBody> res;
      const std::function<void(const boost::beast::http::response<ResBody> &, boost::beast::error_code)> handler;
    };

  private:
    const std::string host, port;

  protected:
    boost::asio::strand<boost::asio::system_executor> strand;

  private:
    boost::asio::signal_set signals;
    boost::asio::ip::tcp::resolver resolver;
    boost::beast::flat_buffer buffer;

  protected:
    std::function<void()> on_connect_handler;
    std::function<void(boost::beast::error_code)> on_error_handler;
    std::function<void()> on_close_handler;

    std::queue<std::shared_ptr<client_request>> requests;
  };

  class plain_client : public client<plain_client>
  {
    friend class client<plain_client>;

  public:
    plain_client(const std::string &host, const std::string &port = "80", const std::function<void()> &on_connect_handler = default_on_connect_handler, const std::function<void(boost::beast::error_code)> &on_error_handler = default_on_error_handler, const std::function<void()> &on_close_handler = default_on_close_handler) : client(host, port, boost::asio::make_strand(boost::asio::system_executor()), on_connect_handler, on_error_handler, on_close_handler), stream(strand) { do_resolve(); }

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
      if (requests.size() == 1) // If we have no work, make this call again..
        requests.front()->handle_request();
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
    ssl_client(const std::string &host, const std::string &port = "443", const std::function<void()> &on_connect_handler = default_on_connect_handler, const std::function<void(boost::beast::error_code)> &on_error_handler = default_on_error_handler, const std::function<void()> &on_close_handler = default_on_close_handler) : client(host, port, boost::asio::make_strand(boost::asio::system_executor()), on_connect_handler, on_error_handler, on_close_handler), stream(strand, ctx)
    {
      // Set SNI Hostname (many hosts need this to handshake successfully)
      if (!SSL_set_tlsext_host_name(stream.native_handle(), host.c_str()))
      {
        boost::beast::error_code ec{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()};
        LOG_ERR("SSL_set_tlsext_host_name: " << ec.message());
        on_error_handler(ec);
        return;
      }

      do_resolve();
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
      if (requests.size() == 1) // If we have no work, make this call again..
        requests.front()->handle_request();
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
    boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv13}; // The SSL context is required, and holds certificates
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream;
  };
} // namespace network
