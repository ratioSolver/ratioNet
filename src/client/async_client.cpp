#include "async_client.hpp"
#include "logging.hpp"

namespace network
{
    async_client_base::async_client_base(std::string_view host, unsigned short port) : host(host), port(port), io_ctx(), resolver(io_ctx), endpoints(resolver.resolve(host, std::to_string(port))) {}
    async_client_base::~async_client_base() {}

    void async_client_base::send(std::unique_ptr<request> req, std::function<void(const response &)> &&cb)
    {
    }

    async_client::async_client(std::string_view host, unsigned short port) : async_client_base(host, port) {}

#ifdef ENABLE_SSL
    ssl_async_client::ssl_async_client(std::string_view host, unsigned short port) : async_client_base(host, port), ssl_ctx(asio::ssl::context::TLS_VERSION)
    {
        ssl_ctx.set_default_verify_paths();
    }
#endif
} // namespace network