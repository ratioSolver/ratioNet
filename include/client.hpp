#pragma once

#include "memory.hpp"
#include "request.hpp"
#include "response.hpp"
#include <queue>
#ifdef ENABLE_SSL
#include <asio/ssl.hpp>
#endif

namespace network
{
  class sync_client
  {
  public:
    sync_client(std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT);
    virtual ~sync_client() = default;

    /**
     * Sends a request and returns the response.
     *
     * @param req The request to be sent.
     * @return The response received.
     */
    utils::u_ptr<response> send(utils::u_ptr<request> req);

    /**
     * Sends a GET request to the specified target with optional headers.
     *
     * @param target The target URL or path.
     * @param hdrs The optional headers to include in the request.
     * @return A unique pointer to the response object.
     */
    utils::u_ptr<response> get(std::string &&target, std::map<std::string, std::string> &&hdrs = {})
    {
      hdrs["Host"] = host + ":" + std::to_string(port);
      return send(utils::make_u_ptr<request>(verb::Get, std::move(target), "HTTP/1.1", std::move(hdrs)));
    }

    /**
     * Sends a POST request to the specified target with optional headers and body.
     *
     * @param target The target URL or path.
     * @param body The body of the request.
     * @param hdrs The optional headers to include in the request.
     * @return A unique pointer to the response object.
     */
    utils::u_ptr<response> post(std::string &&target, std::string &&body, std::map<std::string, std::string> &&hdrs = {})
    {
      hdrs["Host"] = host + ":" + std::to_string(port);
      return send(utils::make_u_ptr<string_request>(verb::Post, std::move(target), "HTTP/1.1", std::move(hdrs), std::move(body)));
    }

    /**
     * Sends a POST request to the specified target with optional headers and JSON body.
     *
     * @param target The target URL or path.
     * @param body The body of the request.
     * @param hdrs The optional headers to include in the request.
     * @return A unique pointer to the response object.
     */
    utils::u_ptr<response> post(std::string &&target, json::json &&body, std::map<std::string, std::string> &&hdrs = {})
    {
      hdrs["Host"] = host + ":" + std::to_string(port);
      return send(utils::make_u_ptr<json_request>(verb::Post, std::move(target), "HTTP/1.1", std::move(hdrs), std::move(body)));
    }

    /**
     * Sends a PUT request to the specified target with optional headers and body.
     *
     * @param target The target URL or path.
     * @param body The body of the request.
     * @param hdrs The optional headers to include in the request.
     * @return A unique pointer to the response object.
     */
    utils::u_ptr<response> put(std::string &&target, std::string &&body, std::map<std::string, std::string> &&hdrs = {})
    {
      hdrs["Host"] = host + ":" + std::to_string(port);
      return send(utils::make_u_ptr<string_request>(verb::Put, std::move(target), "HTTP/1.1", std::move(hdrs), std::move(body)));
    }

    /**
     * Sends a PUT request to the specified target with optional headers and JSON body.
     *
     * @param target The target URL or path.
     * @param body The body of the request.
     * @param hdrs The optional headers to include in the request.
     * @return A unique pointer to the response object.
     */
    utils::u_ptr<response> put(std::string &&target, json::json &&body, std::map<std::string, std::string> &&hdrs = {})
    {
      hdrs["Host"] = host + ":" + std::to_string(port);
      return send(utils::make_u_ptr<json_request>(verb::Put, std::move(target), "HTTP/1.1", std::move(hdrs), std::move(body)));
    }

    /**
     * Sends a DELETE request to the specified target with optional headers.
     *
     * @param target The target URL or path.
     * @param hdrs The optional headers to include in the request.
     * @return A unique pointer to the response object.
     */
    utils::u_ptr<response> del(std::string &&target, std::map<std::string, std::string> &&hdrs = {})
    {
      hdrs["Host"] = host + ":" + std::to_string(port);
      return send(utils::make_u_ptr<request>(verb::Delete, std::move(target), "HTTP/1.1", std::move(hdrs)));
    }

  private:
    virtual bool is_connected() const = 0; // Check if the client is connected to the server.
    virtual asio::ip::tcp::endpoint connect(const asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints) = 0;
    virtual void disconnect() = 0;

    virtual std::size_t read(asio::streambuf &buffer, std::size_t size) = 0;
    virtual std::size_t read_until(asio::streambuf &buffer, std::string_view delimiter) = 0;
    virtual std::size_t write(asio::streambuf &buffer) = 0;

  protected:
    const std::string host;    // The host name of the server.
    const unsigned short port; // The port number of the server.
    asio::io_context io_ctx;   // The I/O context used for asynchronous operations.
  private:
    asio::ip::tcp::resolver resolver;                          // The resolver used to resolve host names.
    asio::ip::basic_resolver_results<asio::ip::tcp> endpoints; // The resolved endpoints for the server.
  protected:
    asio::error_code ec; // Error code for handling errors in operations.
  };

  class client : public sync_client
  {
  public:
    /**
     * @brief Constructs an http_client object with the specified host and port.
     *
     * @param host The host name of the server.
     * @param port The port number of the server.
     */
    client(std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT);
    ~client();

  private:
    bool is_connected() const override;
    asio::ip::tcp::endpoint connect(const asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints) override;
    void disconnect() override;

    std::size_t read(asio::streambuf &buffer, std::size_t size) override;
    std::size_t read_until(asio::streambuf &buffer, std::string_view delimiter) override;
    std::size_t write(asio::streambuf &buffer);

  private:
    asio::ip::tcp::socket socket; // The TCP socket used to communicate with the server.
  };

#ifdef ENABLE_SSL
  class ssl_client : public sync_client
  {
  public:
    /**
     * @brief Constructs an ssl_client object with the specified host and port.
     *
     * @param host The host name of the server.
     * @param port The port number of the server.
     */
    ssl_client(std::string_view host = SERVER_HOST, unsigned short port = SERVER_PORT);
    ~ssl_client();

  private:
    bool is_connected() const override;
    asio::ip::tcp::endpoint connect(const asio::ip::basic_resolver_results<asio::ip::tcp> &endpoints) override;
    void disconnect() override;

    std::size_t read(asio::streambuf &buffer, std::size_t size) override;
    std::size_t read_until(asio::streambuf &buffer, std::string_view delimiter) override;
    std::size_t write(asio::streambuf &buffer);

  private:
    asio::ssl::context ssl_ctx;                      // The SSL context used for secure communication.
    asio::ssl::stream<asio::ip::tcp::socket> socket; // The SSL socket used to communicate with the server.
  };
#endif
} // namespace network
