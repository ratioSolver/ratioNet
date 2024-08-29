#pragma once

#include "request.hpp"
#include "response.hpp"
#include <queue>

namespace network
{
  class client
  {
  public:
    client(const std::string &host = SERVER_HOST, unsigned short port = SERVER_PORT);

    /**
     * Sends a request and returns the response.
     *
     * @param req The request to be sent.
     * @return The response received.
     */
    std::unique_ptr<response> send(std::unique_ptr<request> req);

    /**
     * Sends a GET request to the specified target with optional headers.
     *
     * @param target The target URL or path.
     * @param hdrs The optional headers to include in the request.
     * @return A unique pointer to the response object.
     */
    std::unique_ptr<response> get(std::string &&target, std::map<std::string, std::string> &&hdrs = {}) { return send(std::make_unique<request>(verb::Get, std::move(target), "HTTP/1.1", std::move(hdrs))); }

    /**
     * Sends a POST request to the specified target with optional headers and body.
     *
     * @param target The target URL or path.
     * @param body The body of the request.
     * @param hdrs The optional headers to include in the request.
     * @return A unique pointer to the response object.
     */
    std::unique_ptr<response> post(std::string &&target, std::string &&body, std::map<std::string, std::string> &&hdrs = {}) { return send(std::make_unique<string_request>(verb::Post, std::move(target), "HTTP/1.1", std::move(hdrs), std::move(body))); }

    /**
     * Sends a POST request to the specified target with optional headers and JSON body.
     *
     * @param target The target URL or path.
     * @param body The body of the request.
     * @param hdrs The optional headers to include in the request.
     * @return A unique pointer to the response object.
     */
    std::unique_ptr<response> post(std::string &&target, json::json &&body, std::map<std::string, std::string> &&hdrs = {}) { return send(std::make_unique<json_request>(verb::Post, std::move(target), "HTTP/1.1", std::move(hdrs), std::move(body))); }

    /**
     * Sends a PUT request to the specified target with optional headers and body.
     *
     * @param target The target URL or path.
     * @param body The body of the request.
     * @param hdrs The optional headers to include in the request.
     * @return A unique pointer to the response object.
     */
    std::unique_ptr<response> put(std::string &&target, std::string &&body, std::map<std::string, std::string> &&hdrs = {}) { return send(std::make_unique<string_request>(verb::Put, std::move(target), "HTTP/1.1", std::move(hdrs), std::move(body))); }

    /**
     * Sends a PUT request to the specified target with optional headers and JSON body.
     *
     * @param target The target URL or path.
     * @param body The body of the request.
     * @param hdrs The optional headers to include in the request.
     * @return A unique pointer to the response object.
     */
    std::unique_ptr<response> put(std::string &&target, json::json &&body, std::map<std::string, std::string> &&hdrs = {}) { return send(std::make_unique<json_request>(verb::Put, std::move(target), "HTTP/1.1", std::move(hdrs), std::move(body))); }

    /**
     * Sends a DELETE request to the specified target with optional headers.
     *
     * @param target The target URL or path.
     * @param hdrs The optional headers to include in the request.
     * @return A unique pointer to the response object.
     */
    std::unique_ptr<response> del(std::string &&target, std::map<std::string, std::string> &&hdrs = {}) { return send(std::make_unique<request>(verb::Delete, std::move(target), "HTTP/1.1", std::move(hdrs))); }

    /**
     * @brief Disconnects the client from the server.
     */
    void disconnect();

  private:
    void connect();

  private:
    const std::string host;                  // The host name of the server.
    const unsigned short port;               // The port number of the server.
    asio::io_context io_ctx;          // The I/O context used for asynchronous operations.
    asio::ip::tcp::resolver resolver; // The resolver used to resolve host names.
    asio::ip::tcp::socket socket;     // The socket used to communicate with the server.
  };
} // namespace network
