#include "server.h"

int main()
{
    network::server server;
    
    /*
    server.add_route(boost::beast::http::verb::get, "/hello", [](const network::request_impl<network::plain_http_session, boost::beast::http::string_body, boost::beast::http::fields> &req)
                     { boost::beast::http::response<boost::beast::http::string_body, boost::beast::http::fields> res{ boost::beast::http::status::ok, req.get_version() };
                       return network::response_ptr(new network::response_impl(req.get_session(), std::move(res))); });
    */

    server.start();

    return 0;
}
