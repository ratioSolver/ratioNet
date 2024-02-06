#include "http_session.hpp"
#include "server.hpp"

namespace network
{
    boost::optional<http_handler &> http_session::get_http_handler(boost::beast::http::verb method, const std::string &target) { return srv.get_http_handler(method, target); }
    boost::optional<websocket_handler &> http_session::get_ws_handler(const std::string &target) { return srv.get_ws_handler(target); }

#ifdef USE_SSL
    boost::optional<http_handler &> http_session::get_https_handler(boost::beast::http::verb method, const std::string &target) { return srv.get_https_handler(method, target); }
    boost::optional<websocket_handler &> http_session::get_wss_handler(const std::string &target) { return srv.get_wss_handler(target); }
#endif
} // namespace network
