#include "websocket_session.hpp"
#include "websocket_handler.hpp"

namespace network
{
    void websocket_session::fire_on_open() { handler.on_open_handler(*this); }
    void websocket_session::fire_on_message(const std::string &msg) { handler.on_message_handler(*this, msg); }
    void websocket_session::fire_on_close(boost::beast::websocket::close_reason const &cr) { handler.on_close_handler(*this, cr); }
    void websocket_session::fire_on_error(boost::beast::error_code const &ec) { handler.on_error_handler(*this, ec); }
} // namespace network
