#include "session.hpp"
#include "ws_session.hpp"
#include "server.hpp"
#include "logging.hpp"

namespace network
{
    session::session(server &srv, boost::asio::ip::tcp::socket socket) : srv(srv), socket(std::move(socket)) { LOG_TRACE("Session created with " << this->socket.remote_endpoint()); }
    session::~session() { LOG_TRACE("Session destroyed"); }

    void session::read()
    {
        req = std::make_unique<request>();
        boost::asio::async_read_until(socket, req->buffer, "\r\n\r\n", std::bind(&session::on_read, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
    }

    void session::enqueue(std::unique_ptr<response> res)
    {
        boost::asio::post(socket.get_executor(), [self = shared_from_this(), r = std::move(res)]() mutable
                          { self->res_queue.push(std::move(r));
                            if (self->res_queue.size() == 1)
                                self->write(); });
    }
    void session::write()
    {
        LOG_DEBUG(*res_queue.front());
        boost::asio::async_write(socket, res_queue.front()->get_buffer(), std::bind(&session::on_write, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
    }

    void session::upgrade()
    {
        enqueue(std::make_unique<response>(status_code::websocket_switching_protocols, std::map<std::string, std::string>{{"Upgrade", "websocket"}, {"Connection", "Upgrade"}}));
        std::make_shared<ws_session>(srv, std::move(socket))->read();
    }

    void session::on_read(const boost::system::error_code &ec, std::size_t bytes_transferred)
    {
        if (ec == boost::asio::error::eof)
            return; // connection closed by client
        else if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        std::istream is(&req->buffer);

        switch (is.get())
        {
        case 'D':
            if (is.get() == 'E' && is.get() == 'L' && is.get() == 'E' && is.get() == 'T' && is.get() == 'E')
                req->v = DELETE;
            break;
        case 'G':
            if (is.get() == 'E' && is.get() == 'T')
                req->v = GET;
            break;
        case 'P':
            switch (is.get())
            {
            case 'O':
                if (is.get() == 'S' && is.get() == 'T')
                    req->v = POST;
                break;
            case 'U':
                if (is.get() == 'T')
                    req->v = PUT;
                break;
            }
            break;
        }
        is.get(); // consume space

        while (is.peek() != ' ')
            req->target += is.get();
        is.get(); // consume space

        while (is.peek() != '\r')
            req->version += is.get();
        is.get(); // consume '\r'
        is.get(); // consume '\n'

        while (is.peek() != '\r')
        {
            std::string header, value;
            while (is.peek() != ':')
                header += is.get();
            is.get(); // consume ':'
            is.get(); // consume space
            while (is.peek() != '\r')
                value += is.get();
            is.get(); // consume '\r'
            is.get(); // consume '\n'
            req->headers.emplace(std::move(header), std::move(value));
        }
        is.get(); // consume '\r'
        is.get(); // consume '\n'

        if (req->headers.find("Upgrade") != req->headers.end() && req->headers["Upgrade"] == "websocket") // handle websocket upgrade request
            return upgrade();

        bool keep_alive = req->headers.find("Connection") != req->headers.end() && req->headers["Connection"] == "keep-alive";

        if (req->headers.find("Content-Length") != req->headers.end())
        { // read body
            std::size_t content_length = std::stoul(req->headers["Content-Length"]);
            if (content_length > bytes_transferred) // the buffer may contain additional bytes beyond the delimiter
                boost::asio::async_read(socket, req->buffer, boost::asio::transfer_exactly(content_length - bytes_transferred), std::bind(&session::on_body, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
            else // the buffer contains the entire body
                on_body(ec, bytes_transferred);
        }
        else
            srv.handle_request(*this, std::move(req));

        if (keep_alive)
            read(); // read next request
    }

    void session::on_body(const boost::system::error_code &ec, std::size_t bytes_transferred)
    {
        if (ec == boost::asio::error::eof)
            return; // connection closed by client
        else if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        std::istream is(&req->buffer);
        if (req->headers.find("Content-Type") != req->headers.end() && req->headers["Content-Type"] == "application/json")
            req = std::make_unique<json_request>(req->v, std::move(req->target), std::move(req->version), std::move(req->headers), json::load(is));
        else
        {
            std::string body;
            while (is.peek() != EOF)
                body += is.get();
            req = std::make_unique<string_request>(req->v, std::move(req->target), std::move(req->version), std::move(req->headers), std::move(body));
        }
        srv.handle_request(*this, std::move(req));
    }

    void session::on_write(const boost::system::error_code &ec, std::size_t bytes_transferred)
    {
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        res_queue.pop();
        if (!res_queue.empty())
            write();
    }
} // namespace network
