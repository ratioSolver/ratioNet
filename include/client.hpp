#pragma once

#include <boost/beast.hpp>
#include <boost/asio.hpp>
#ifdef USE_SSL
#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>
#endif

namespace network
{
  template <class Derived>
  class base_client
  {
    Derived &derived() { return static_cast<Derived &>(*this); }

  public:
    base_client(const std::string &host = SERVER_ADDRESS, const std::string &port = SERVER_PORT) : host(host), port(port), resolver(ioc)
    {
      boost::beast::error_code ec;
      auto results = resolver.resolve(host, port, ec);
      if (ec)
        throw boost::beast::system_error{ec};
    }
    virtual ~base_client() = default;

    virtual void connect() = 0;

    /**
     * @brief Send a GET request.
     *
     * @param target The target of the request.
     * @param fields The fields to send with the request.
     */
    template <class Body>
    boost::beast::http::response<Body> get(const std::string &target, const std::unordered_map<boost::beast::http::field, std::string> &fields = {})
    {
      boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::get, target, 11};
      req.set(boost::beast::http::field::host, host);
      req.set(boost::beast::http::field::user_agent, "ratioNet");
      for (auto &field : fields)
        req.set(field.first, field.second);
      return send<boost::beast::http::string_body, Body>(std::move(req));
    }

    /**
     * @brief Send a POST request.
     *
     * @param target The target of the request.
     * @param body The body of the request.
     * @param fields The fields to send with the request.
     */
    template <class Body>
    boost::beast::http::response<Body> post(const std::string &target, const std::string &body, const std::unordered_map<boost::beast::http::field, std::string> &fields = {})
    {
      boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::post, target, 11};
      req.set(boost::beast::http::field::host, host);
      req.set(boost::beast::http::field::user_agent, "ratioNet");
      for (auto &field : fields)
        req.set(field.first, field.second);
      req.body() = body;
      return send<boost::beast::http::string_body, Body>(std::move(req));
    }

    /**
     * @brief Send a PUT request.
     *
     * @param target The target of the request.
     * @param body The body of the request.
     * @param fields The fields to send with the request.
     */
    template <class Body>
    boost::beast::http::response<Body> put(const std::string &target, const std::string &body, const std::unordered_map<boost::beast::http::field, std::string> &fields = {})
    {
      boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::put, target, 11};
      req.set(boost::beast::http::field::host, host);
      req.set(boost::beast::http::field::user_agent, "ratioNet");
      for (auto &field : fields)
        req.set(field.first, field.second);
      req.body() = body;
      return send<boost::beast::http::string_body, Body>(std::move(req));
    }

    /**
     * @brief Send a PATCH request.
     *
     * @param target The target of the request.
     * @param body The body of the request.
     * @param fields The fields to send with the request.
     */
    template <class Body>
    boost::beast::http::response<Body> patch(const std::string &target, const std::string &body, const std::unordered_map<boost::beast::http::field, std::string> &fields = {})
    {
      boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::patch, target, 11};
      req.set(boost::beast::http::field::host, host);
      req.set(boost::beast::http::field::user_agent, "ratioNet");
      for (auto &field : fields)
        req.set(field.first, field.second);
      req.body() = body;
      return send<boost::beast::http::string_body, Body>(std::move(req));
    }

    /**
     * @brief Send a DELETE request.
     *
     * @param target The target of the request.
     * @param fields The fields to send with the request.
     */
    template <class Body>
    boost::beast::http::response<Body> del(const std::string &target, const std::unordered_map<boost::beast::http::field, std::string> &fields = {})
    {
      boost::beast::http::request<boost::beast::http::empty_body> req{boost::beast::http::verb::delete_, target, 11};
      req.set(boost::beast::http::field::host, host);
      req.set(boost::beast::http::field::user_agent, "ratioNet");
      for (auto &field : fields)
        req.set(field.first, field.second);
      return send<boost::beast::http::empty_body, Body>(std::move(req));
    }

    template <class ReqBody, class ResBody>
    boost::beast::http::response<ResBody> send(boost::beast::http::request<ReqBody> &&req)
    {
      req.prepare_payload();
      boost::beast::http::response<ResBody> res;
      boost::beast::get_lowest_layer(derived().get_stream()).expires_after(std::chrono::seconds(30));
      boost::beast::error_code ec;
      boost::beast::http::write(derived().get_stream(), req, ec);
      if (ec)
        throw boost::beast::system_error{ec};
      boost::beast::flat_buffer buffer;
      boost::beast::http::read(derived().get_stream(), buffer, res, ec);
      if (ec)
        throw boost::beast::system_error{ec};
      return res;
    }

    virtual void disconnect() = 0;

  protected:
    std::string host;
    std::string port;
    boost::asio::io_context ioc;
    boost::asio::ip::tcp::resolver resolver;
    boost::beast::flat_buffer buffer;
  };

  class client : public base_client<client>
  {
  public:
    client(const std::string &host = SERVER_ADDRESS, const std::string &port = SERVER_PORT) : base_client(host, port) { connect(); }
    ~client() { disconnect(); }

    boost::beast::tcp_stream &get_stream() { return stream; }

    void connect() override { stream.connect(resolver.resolve(host, port)); }
    void disconnect() override
    {
      boost::beast::error_code ec;
      stream.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
      if (ec == boost::asio::error::eof)
      {
        // Rationale:
        // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
        ec = {};
      }
      if (ec)
        throw boost::beast::system_error{ec};
    }

  protected:
    boost::beast::tcp_stream stream{ioc};
  };

#ifdef USE_SSL
  class ssl_client : public base_client<ssl_client>
  {
  public:
    ssl_client(const std::string &host = SERVER_ADDRESS, const std::string &port = SERVER_PORT) : base_client(host, port)
    {
      // Set SNI Hostname (many hosts need this to handshake successfully)
      if (!SSL_set_tlsext_host_name(stream.native_handle(), host.c_str()))
        throw boost::beast::system_error{boost::beast::error_code{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()}};

      connect();
    }
    ~ssl_client() { disconnect(); }

    boost::beast::ssl_stream<boost::beast::tcp_stream> &get_stream() { return stream; }

    void connect() override
    {
      stream.next_layer().connect(resolver.resolve(host, port));
      stream.handshake(boost::asio::ssl::stream_base::client);
    }
    void disconnect() override
    {
      boost::beast::error_code ec;
      stream.next_layer().socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
      if (ec == boost::asio::error::eof)
      {
        // Rationale:
        // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
        ec = {};
      }
      if (ec)
        throw boost::beast::system_error{ec};
    }

  protected:
    boost::asio::ssl::context ssl_ctx{boost::asio::ssl::context::TLS_VERSION};
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream{ioc, ssl_ctx};
  };
#endif
} // namespace network
