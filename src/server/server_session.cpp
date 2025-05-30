#include "server_session.hpp"
#include "logging.hpp"

namespace network
{
    server_session_base::server_session_base(server_base &server) : server(server) {}
    server_session_base::~server_session_base() {}

    server_session::server_session(server_base &server, asio::ip::tcp::socket &&socket) : server_session_base(server), socket(std::move(socket))
    {
    }
} // namespace network
