#include "session_detector.h"
#include "logging.h"
#include <boost/asio/dispatch.hpp>

namespace network
{
    session_detector::session_detector(boost::asio::ip::tcp::socket &&socket, boost::asio::ssl::context &ctx) : stream(std::move(socket)), ctx(ctx)
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
        }
        else
        {
            LOG_DEBUG("Plain HTTP connection detected");
        }
        delete this;
    }
} // namespace network
