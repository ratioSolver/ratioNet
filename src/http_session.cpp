#include "http_session.h"

namespace network
{
    plain_http_session::plain_http_session(boost::beast::tcp_stream &&stream, boost::beast::flat_buffer &&buffer) : http_session(std::move(buffer)), stream(std::move(stream)) {}

    ssl_http_session::ssl_http_session(boost::beast::tcp_stream &&stream, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&buffer) : http_session(std::move(buffer)), stream(std::move(stream), ctx) {}
} // namespace network
