#include "http_session.h"

namespace network
{
    http_session::http_session(boost::beast::tcp_stream &&stream, boost::beast::flat_buffer &&buffer) : stream(std::move(stream)), buffer(std::move(buffer))
    {
    }
} // namespace network