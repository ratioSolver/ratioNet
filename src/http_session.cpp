#include "http_session.h"
#include "websocket_session.h"
#include "server.h"
#include "logging.h"
#include <fstream>

namespace network
{
    const std::unordered_map<std::string, std::string> mime_types{
        {"shtml", "text/html"},
        {"htm", "text/html"},
        {"html", "text/html"},
        {"css", "text/css"},
        {"xml", "text/xml"},
        {"gif", "image/gif"},
        {"jpg", "image/jpeg"},
        {"jpeg", "image/jpeg"},
        {"js", "application/javascript"},
        {"atom", "application/atom+xml"},
        {"rss", "application/rss+xml"},
        {"mml", "text/mathml"},
        {"txt", "text/plain"},
        {"jad", "text/vnd.sun.j2me.app-descriptor"},
        {"wml", "text/vnd.wap.wml"},
        {"htc", "text/x-component"},
        {"avif", "image/avif"},
        {"png", "image/png"},
        {"svgz", "image/svg+xml"},
        {"svg", "image/svg+xml"},
        {"tiff", "image/tiff"},
        {"tif", "image/tiff"},
        {"wbmp", "image/vnd.wap.wbmp"},
        {"webp", "image/webp"},
        {"ico", "image/x-icon"},
        {"jng", "image/x-jng"},
        {"bmp", "image/x-ms-bmp"},
        {"woff", "font/woff"},
        {"woff2", "font/woff2"},
        {"ear", "application/java-archive"},
        {"war", "application/java-archive"},
        {"jar", "application/java-archive"},
        {"json", "application/json"},
        {"hqx", "application/mac-binhex40"},
        {"doc", "application/msword"},
        {"pdf", "application/pdf"},
        {"ai", "application/postscript"},
        {"eps", "application/postscript"},
        {"ps", "application/postscript"},
        {"rtf", "application/rtf"},
        {"m3u8", "application/vnd.apple.mpegurl"},
        {"kml", "application/vnd.google-earth.kml+xml"},
        {"kmz", "application/vnd.google-earth.kmz"},
        {"xls", "application/vnd.ms-excel"},
        {"eot", "application/vnd.ms-fontobject"},
        {"ppt", "application/vnd.ms-powerpoint"},
        {"odg", "application/vnd.oasis.opendocument.graphics"},
        {"odp", "application/vnd.oasis.opendocument.presentation"},
        {"ods", "application/vnd.oasis.opendocument.spreadsheet"},
        {"odt", "application/vnd.oasis.opendocument.text"},
        {"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
        {"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
        {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        {"wmlc", "application/vnd.wap.wmlc"},
        {"wasm", "application/wasm"},
        {"7z", "application/x-7z-compressed"},
        {"cco", "application/x-cocoa"},
        {"jardiff", "application/x-java-archive-diff"},
        {"jnlp", "application/x-java-jnlp-file"},
        {"run", "application/x-makeself"},
        {"pm", "application/x-perl"},
        {"pl", "application/x-perl"},
        {"pdb", "application/x-pilot"},
        {"prc", "application/x-pilot"},
        {"rar", "application/x-rar-compressed"},
        {"rpm", "application/x-redhat-package-manager"},
        {"sea", "application/x-sea"},
        {"swf", "application/x-shockwave-flash"},
        {"sit", "application/x-stuffit"},
        {"tk", "application/x-tcl"},
        {"tcl", "application/x-tcl"},
        {"crt", "application/x-x509-ca-cert"},
        {"pem", "application/x-x509-ca-cert"},
        {"der", "application/x-x509-ca-cert"},
        {"xpi", "application/x-xpinstall"},
        {"xhtml", "application/xhtml+xml"},
        {"xspf", "application/xspf+xml"},
        {"zip", "application/zip"},
        {"dll", "application/octet-stream"},
        {"exe", "application/octet-stream"},
        {"bin", "application/octet-stream"},
        {"deb", "application/octet-stream"},
        {"dmg", "application/octet-stream"},
        {"img", "application/octet-stream"},
        {"iso", "application/octet-stream"},
        {"msm", "application/octet-stream"},
        {"msp", "application/octet-stream"},
        {"msi", "application/octet-stream"},
        {"kar", "audio/midi"},
        {"midi", "audio/midi"},
        {"mid", "audio/midi"},
        {"mp3", "audio/mpeg"},
        {"ogg", "audio/ogg"},
        {"m4a", "audio/x-m4a"},
        {"ra", "audio/x-realaudio"},
        {"3gp", "video/3gpp"},
        {"3gpp", "video/3gpp"},
        {"ts", "video/mp2t"},
        {"mp4", "video/mp4"},
        {"mpg", "video/mpeg"},
        {"mpeg", "video/mpeg"},
        {"mov", "video/quicktime"},
        {"webm", "video/webm"},
        {"flv", "video/x-flv"},
        {"m4v", "video/x-m4v"},
        {"mng", "video/x-mng"},
        {"asf", "video/x-ms-asf"},
        {"asx", "video/x-ms-asf"},
        {"wmv", "video/x-ms-wmv"},
        {"avi", "video/x-msvideo"}};

    http_session::http_session(server &srv, boost::asio::ip::tcp::socket &&socket) : srv(srv), socket(std::move(socket)) {}
    http_session::~http_session() {}

    void http_session::run()
    {
        boost::beast::http::async_read(socket, buffer, req, [this](boost::system::error_code ec, std::size_t bytes_transferred)
                                       { on_read(ec, bytes_transferred); });
    }

    void http_session::on_read(boost::system::error_code ec, std::size_t)
    {
        LOG_DEBUG("HTTP request: " << req.method_string() << " " << req.target());
        if (ec == boost::beast::http::error::end_of_stream)
        {
            socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
            return;
        }
        else if (ec)
        {
            delete this;
            return;
        }

        bool found = false;
        if (boost::beast::websocket::is_upgrade(req))
        {
            for (auto &handler : srv.ws_routes)
                if (std::regex_match(req.target().to_string(), handler.first))
                {
                    found = true;
                    (new websocket_session(srv, std::move(socket), handler.second))->run(std::move(req));
                    break;
                }
            if (!found)
                LOG_WARN("No WebSocket handler found for " << req.target());
            delete this;
            return;
        }

        if (req.target().to_string().substr(0, srv.file_server_root.size()) == srv.file_server_root)
        {
            std::string path = req.target().to_string();
            if (path.size() > 255)
            {
                LOG_WARN("File path too long: " << path);
                delete this;
                return;
            }
            if (path.find("..") != std::string::npos)
            {
                LOG_WARN("File path contains '..': " << path);
                delete this;
                return;
            }

            auto res = new boost::beast::http::response<boost::beast::http::file_body>{boost::beast::http::status::ok, req.version()};
            res->set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
            auto mime_type_it = mime_types.find(path.substr(path.find_last_of('.') + 1));
            res->set(boost::beast::http::field::content_type, mime_type_it != mime_types.end() ? mime_type_it->second : "application/octet-stream");
            res->body().open(('.' + path).c_str(), boost::beast::file_mode::read, ec);
            if (ec)
            {
                LOG_WARN("File not found: " << req.target());
                res->result(boost::beast::http::status::not_found);
                res->body().close();
            }
            boost::beast::http::async_write(socket, *res, [this, res](boost::system::error_code ec, std::size_t bytes_transferred)
                                            { on_write(ec, bytes_transferred, res->need_eof()); delete res; });
            return;
        }

        auto res = new boost::beast::http::response<boost::beast::http::string_body>{boost::beast::http::status::ok, req.version()};
        switch (req.method())
        {
        case boost::beast::http::verb::get:
            for (auto &handler : srv.get_routes)
                if (std::regex_match(req.target().to_string(), handler.first))
                {
                    found = true;
                    handler.second(req, *res);
                    break;
                }
            break;
        case boost::beast::http::verb::post:
            for (auto &handler : srv.post_routes)
                if (std::regex_match(req.target().to_string(), handler.first))
                {
                    found = true;
                    handler.second(req, *res);
                    break;
                }
            break;
        case boost::beast::http::verb::put:
            for (auto &handler : srv.put_routes)
                if (std::regex_match(req.target().to_string(), handler.first))
                {
                    found = true;
                    handler.second(req, *res);
                    break;
                }
            break;
        case boost::beast::http::verb::delete_:
            for (auto &handler : srv.delete_routes)
                if (std::regex_match(req.target().to_string(), handler.first))
                {
                    found = true;
                    handler.second(req, *res);
                    break;
                }
            break;
        default:
            res->result(boost::beast::http::status::bad_request);
            res->set(boost::beast::http::field::content_type, "text/plain");
            res->body() = "Invalid request method";
            break;
        }
        if (!found)
        {
            res->result(boost::beast::http::status::not_found);
            res->set(boost::beast::http::field::content_type, "text/plain");
            res->body() = "The resource '" + req.target().to_string() + "' was not found.";
        }
        res->prepare_payload();

        boost::beast::http::async_write(socket, *res, [this, res](boost::system::error_code ec, std::size_t bytes_transferred)
                                        { on_write(ec, bytes_transferred, res->need_eof()); delete res; });
    }

    void http_session::on_write(boost::system::error_code ec, std::size_t, bool close)
    {
        if (ec)
        {
            delete this;
            return;
        }

        if (close)
        {
            socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
            delete this;
            return;
        }

        req = {};
        buffer.consume(buffer.size());

        boost::beast::http::async_read(socket, buffer, req, [this](boost::system::error_code ec, std::size_t bytes_transferred)
                                       { on_read(ec, bytes_transferred); });
    }
} // namespace network
