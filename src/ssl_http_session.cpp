#include "ssl_http_session.h"

namespace network
{
    ssl_http_session::ssl_http_session(boost::beast::tcp_stream &&stream, boost::asio::ssl::context &ctx, boost::beast::flat_buffer &&buffer) : stream(std::move(stream), ctx), buffer(std::move(buffer))
    {
    }
} // namespace network