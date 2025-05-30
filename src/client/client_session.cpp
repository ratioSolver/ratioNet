#include "client_session.hpp"
#include "async_client.hpp"
#include "logging.hpp"

namespace network
{
    client_session_base::client_session_base(async_client_base &client) : client(client), strand(asio::make_strand(client.io_ctx)) {}
    client_session_base::~client_session_base() {}

    client_session::client_session(async_client_base &client, asio::ip::tcp::socket &&socket) : client_session_base(client), socket(std::move(socket))
    {
    }
} // namespace network
