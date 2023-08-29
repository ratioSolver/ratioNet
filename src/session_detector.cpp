#include "session_detector.h"
#include "logging.h"
#include "http_session.h"
#include "ssl_http_session.h"
#include <boost/asio/dispatch.hpp>

namespace network
{
    session_detector::session_detector(server &srv, boost::asio::ip::tcp::socket &&socket, boost::asio::ssl::context &ctx) : srv(srv), stream(std::move(socket)), ctx(ctx)
    {
        boost::asio::dispatch(stream.get_executor(), [this]
                              { boost::beast::async_detect_ssl(stream, buffer, [this](boost::beast::error_code ec, bool result)
                                                               { on_detect(ec, result); }); });
    }

    void session_detector::on_detect(boost::beast::error_code ec, bool result)
    {
        if (ec)
            LOG_ERR(ec.message());
        else if (result)
        {
            LOG_DEBUG("SSL connection detected");
            new ssl_http_session(srv, std::move(stream), ctx, std::move(buffer));
        }
        else
        {
            LOG_DEBUG("Plain HTTP connection detected");
            new http_session(srv, std::move(stream), std::move(buffer));
        }
        delete this;
    }
} // namespace network
