#include "server.h"
#include "logging.h"

namespace network
{
    server::server(std::string address, unsigned short port) : ctx(), acceptor(ctx, boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address(address), port)), socket(ctx) {}

    void server::run()
    {
        LOG("Server listening on " << acceptor.local_endpoint() << "..");
        do_accept();
        ctx.run();
    }

    void server::do_accept()
    {
        acceptor.async_accept(socket, [this](boost::system::error_code ec)
                              {
                                  if (!ec)
                                  {
                                      boost::beast::flat_buffer buffer;
                                      boost::beast::http::request<boost::beast::http::string_body> request;
                                      boost::beast::http::read(socket, buffer, request);

                                      boost::beast::http::response<boost::beast::http::string_body> response;
                                      response.version(request.version());
                                      response.keep_alive(request.keep_alive());

                                      switch (request.method())
                                      {
                                      case boost::beast::http::verb::get:
                                          for (auto &route : get_routes)
                                              if (std::regex_match(request.target().to_string(), route.first))
                                              {
                                                  route.second(request, response);
                                                  break;
                                              }
                                          break;
                                      case boost::beast::http::verb::post:
                                          for (auto &route : post_routes)
                                              if (std::regex_match(request.target().to_string(), route.first))
                                              {
                                                  route.second(request, response);
                                                  break;
                                              }
                                          break;
                                      case boost::beast::http::verb::put:
                                          for (auto &route : put_routes)
                                              if (std::regex_match(request.target().to_string(), route.first))
                                              {
                                                  route.second(request, response);
                                                  break;
                                              }
                                          break;
                                      case boost::beast::http::verb::delete_:
                                          for (auto &route : delete_routes)
                                              if (std::regex_match(request.target().to_string(), route.first))
                                              {
                                                  route.second(request, response);
                                                  break;
                                              }
                                          break;
                                      default:
                                          response.result(boost::beast::http::status::bad_request);
                                          response.body() = "Invalid request method";
                                          break;
                                      }

                                      boost::beast::http::write(socket, response);
                                      socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
                                      socket.close(ec);
                                  }
                                  else
                                      LOG_ERR("Error accepting connection: " << ec.message());

                                  do_accept(); });
    }

    void server::add_route(boost::beast::http::verb method, std::string regex, std::function<void(boost::beast::http::request<boost::beast::http::string_body> &, boost::beast::http::response<boost::beast::http::string_body> &)> callback)
    {
        switch (method)
        {
        case boost::beast::http::verb::get:
            get_routes.push_back(std::make_pair(std::regex(regex), callback));
            break;
        case boost::beast::http::verb::post:
            post_routes.push_back(std::make_pair(std::regex(regex), callback));
            break;
        case boost::beast::http::verb::put:
            put_routes.push_back(std::make_pair(std::regex(regex), callback));
            break;
        case boost::beast::http::verb::delete_:
            delete_routes.push_back(std::make_pair(std::regex(regex), callback));
            break;
        default:
            LOG_ERR("Invalid request method");
            break;
        }
    }
} // namespace network