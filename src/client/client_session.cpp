#include "client_session.hpp"
#include "logging.hpp"

namespace network
{
    client_session_base::client_session_base(client_base &client) : client(client) {}
    client_session_base::~client_session_base() {}

    client_session::client_session(client_base &client, asio::ip::tcp::socket &&socket) : client_session_base(client), socket(std::move(socket))
    {
    }
} // namespace network
