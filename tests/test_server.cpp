#include <boost/beast/http.hpp>
#include "async_server.hpp"

using string_req = boost::beast::http::request<boost::beast::http::string_body>;
using string_res = boost::beast::http::response<boost::beast::http::string_body>;

void test_plain_async_server()
{
    network::async::server s;
}

int main(int argc, char const *argv[])
{
    return 0;
}
