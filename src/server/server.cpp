#include "server.hpp"
#include "logging.hpp"

namespace network
{
    server_base::server_base(std::string_view host, unsigned short port, std::size_t concurrency_hint) : io_ctx(static_cast<int>(concurrency_hint)), signals(io_ctx, SIGINT, SIGTERM), endpoint(asio::ip::make_address(host), port), acceptor(asio::make_strand(io_ctx))
    {
        threads.reserve(concurrency_hint);
        signals.async_wait([this](const std::error_code &ec, [[maybe_unused]] int signal)
                           {
                               if (!ec)
                               {
                                   LOG_DEBUG("Received signal " + std::to_string(signal));
                                   stop();
                               } });
    }

    server_base::~server_base() { stop(); }
} // namespace network