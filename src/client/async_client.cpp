#include "async_client.hpp"
#include "logging.hpp"

namespace network
{
    async_client_base::async_client_base(std::string_view host, unsigned short port) : host(host), port(port), io_ctx(), resolver(io_ctx), endpoints(resolver.resolve(host, std::to_string(port))) {}
} // namespace network