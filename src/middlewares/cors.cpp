#include "cors.hpp"
#include "server.hpp"
#include <cassert>

namespace network
{
    cors::cors(server_base &srv) : middleware(srv)
    {
        for (auto &[v, rs] : srv.get_routes())
            if (v != verb::Options)
                for (auto &r : rs)
                    srv.add_route(Options, r.get_pattern(), std::bind(&cors::option_route, this, std::placeholders::_1));
    }

    void cors::added_route(verb v, const route &r)
    {
        if (v != verb::Options)
            srv.add_route(Options, r.get_pattern(), std::bind(&cors::option_route, this, std::placeholders::_1));
    }

    void cors::after_request(const request &, response &res) { res.add_header("Access-Control-Allow-Origin", "*"); }

    std::unique_ptr<response> cors::option_route([[maybe_unused]] const request &req)
    {
        assert(req.get_verb() == Options);
        auto res = std::make_unique<response>(status_code::no_content);
        res->add_header("Access-Control-Allow-Origin", "*");
        res->add_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res->add_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        return res;
    }
} // namespace network
