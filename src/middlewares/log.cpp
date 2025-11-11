#include "log.hpp"
#include "server.hpp"
#include "logging.hpp"

namespace network
{
    log::log(server_base &srv) : middleware(srv) {}

    std::unique_ptr<response> log::before_request(const request &req)
    {
        LOG_TRACE(req);
        return nullptr;
    }
    void log::after_request(const request &, response &res) { LOG_TRACE(res); }
} // namespace network
