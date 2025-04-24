#include "server.hpp"
#include "logging.hpp"
#ifdef _WIN32
// Windows-specific code
#define SIGQUIT 3 // Define a dummy value for SIGQUIT on Windows if necessary
#endif
#include <csignal>
#ifdef ENABLE_SSL
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iomanip>
#endif

namespace network
{
    server::server(std::string_view host, unsigned short port, std::size_t concurrency_hint) : io_ctx(static_cast<int>(concurrency_hint)), signals(io_ctx, SIGINT, SIGTERM), endpoint(asio::ip::make_address(host), port), acceptor(asio::make_strand(io_ctx))
    {
        threads.reserve(concurrency_hint);
        signals.async_wait([this](const std::error_code &ec, [[maybe_unused]] int signal)
                           {
                               if (!ec)
                               {
                                   LOG_DEBUG("Received signal " + std::to_string(signal));
                                   stop();
                               } });

#ifdef ENABLE_SSL
        add_route(verb::Post, "^/login$", std::bind(&server::login, this, placeholders::request));
#endif
    }
    server::~server()
    {
        if (running)
            stop();
    }

    void server::start()
    {
        LOG_DEBUG("Starting server on " + endpoint.address().to_string() + ":" + std::to_string(endpoint.port()));

        std::error_code ec;
        acceptor.open(endpoint.protocol(), ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
        acceptor.set_option(asio::socket_base::reuse_address(true), ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
        acceptor.bind(endpoint, ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }
        acceptor.listen(asio::socket_base::max_listen_connections, ec);
        if (ec)
        {
            LOG_ERR(ec.message());
            return;
        }

        running = true;
        do_accept();

        for (auto i = threads.capacity(); i > 0; --i)
            threads.emplace_back([this]
                                 { io_ctx.run(); });

        io_ctx.run();
    }

    void server::stop()
    {
        LOG_DEBUG("Stopping server");
        io_ctx.stop();
        for (auto &thread : threads)
            thread.join();
        running = false;
    }

#ifdef ENABLE_SSL
    void server::add_route(verb v, std::string_view path, std::function<utils::u_ptr<response>(request &)> &&handler, bool auth) noexcept
#else
    void server::add_route(verb v, std::string_view path, std::function<utils::u_ptr<response>(request &)> &&handler) noexcept
#endif
    {
#ifdef ENABLE_SSL
        routes[v].emplace_back(std::regex(path.data()), std::move(handler), auth);
#else
        routes[v].emplace_back(std::regex(path.data()), std::move(handler));
#endif
#ifdef ENABLE_CORS
        if (v != verb::Options)
            routes[verb::Options].emplace_back(std::regex(path), std::bind(&server::cors, this, placeholders::request));
#endif
    }

#ifdef ENABLE_SSL
    void server::load_certificate(std::string_view cert_file, std::string_view key_file)
    {
        LOG_DEBUG("Loading certificate: " + std::string(cert_file));
        ctx.use_certificate_chain_file(cert_file.data());
        LOG_DEBUG("Loading private key: " + std::string(key_file));
        ctx.use_private_key_file(key_file.data(), asio::ssl::context::pem);
    }
#endif

#ifdef ENABLE_SSL
    utils::u_ptr<response> server::login(const request &req)
    {
        auto &body = static_cast<const json_request &>(req).get_body();
        if (body.get_type() != json::json_type::object || !body.contains("username") || body["username"].get_type() != json::json_type::string || !body.contains("password") || body["password"].get_type() != json::json_type::string)
            return utils::make_u_ptr<json_response>(json::json({{"message", "Invalid request"}}), status_code::bad_request);
        std::string username = body["username"];
        std::string password = body["password"];
        try
        {
            auto token = get_token(username, password);
            if (token.empty())
                return utils::make_u_ptr<json_response>(json::json({{"message", "Unauthorized"}}), status_code::unauthorized);
            return utils::make_u_ptr<json_response>(json::json({{"token", token.c_str()}}), status_code::ok);
        }
        catch (const std::exception &e)
        {
            return utils::make_u_ptr<json_response>(json::json({{"message", e.what()}}), status_code::conflict);
        }
    }

    std::string server::get_token(const request &req) const
    {
        if (auto it = req.get_headers().find("authorization"); it != req.get_headers().end())
        {
            std::string bearer = it->second;
            if (bearer.size() > 7 && bearer.substr(0, 7) == "Bearer ")
                return bearer.substr(7);
        }
        return {};
    }
#endif

    void server::do_accept() { acceptor.async_accept(asio::make_strand(io_ctx), std::bind(&server::on_accept, this, asio::placeholders::error, std::placeholders::_2)); }

    void server::on_accept(const std::error_code &ec, asio::ip::tcp::socket socket)
    {
        if (!ec)
#ifdef ENABLE_SSL
            std::make_shared<session>(*this, asio::ssl::stream<asio::ip::tcp::socket>(std::move(socket), ctx))->handshake();
#else
            std::make_shared<session>(*this, std::move(socket))->read();
#endif
        do_accept();
    }

    void server::handle_request(session &s, utils::u_ptr<request> req)
    {
        // read next request if connection is keep-alive
        if (req->is_keep_alive())
            s.read(); // read next request

        if (auto it = routes.find(req->get_verb()); it != routes.end())
            for (const auto &r : it->second)
                if (std::regex_match(req->get_target(), r.get_path()))
                {
#ifdef ENABLE_SSL
                    if (req->get_verb() != verb::Options && r.requires_auth() && get_token(*req).empty())
                    {
                        LOG_WARN("Unauthorized");
                        auto res = utils::make_u_ptr<json_response>(json::json{{"message", "Unauthorized"}}, status_code::unauthorized);
                        s.enqueue(std::move(res));
                        return;
                    }
#endif
                    try
                    {
                        // call the route handler
                        auto res = r.get_handler()(*req);
#ifdef ENABLE_CORS
                        res->headers["Access-Control-Allow-Origin"] = "*";
#endif
                        s.enqueue(std::move(res));
                    }
                    catch (const std::exception &e)
                    {
                        LOG_ERR(e.what());
                        auto res = utils::make_u_ptr<json_response>(json::json{{"message", "Internal Server Error"}}, status_code::internal_server_error);
                        s.enqueue(std::move(res));
                    }
                    return;
                }

        LOG_WARN("No route for " + req->get_target());
        json::json msg = {{"message", "Not Found"}};
        auto res = utils::make_u_ptr<json_response>(json::json(msg), status_code::not_found);
        s.enqueue(std::move(res));
    }

    void server::on_connect(ws_session &s)
    {
        if (auto it = ws_routes.find(s.path); it != ws_routes.end())
            it->second.on_open_handler(s);
        else
            LOG_WARN("No route for " + s.path);
    }
    void server::on_disconnect(ws_session &s)
    {
        if (auto it = ws_routes.find(s.path); it != ws_routes.end())
            it->second.on_close_handler(s);
        else
            LOG_WARN("No route for " + s.path);
    }

    void server::on_message(ws_session &s, utils::u_ptr<message> msg)
    {
        switch (msg->get_fin_rsv_opcode() & 0x0F)
        {
        case 0x00: // continuation
        case 0x01: // text
        case 0x02: // binary
            if (auto it = ws_routes.find(s.path); it != ws_routes.end())
                it->second.on_message_handler(s, msg->get_payload());
            else
                LOG_WARN("No route for " + s.path);
            break;
        case 0x08: // close
            s.close();
            break;
        case 0x09: // ping
            s.pong();
            break;
        case 0x0A: // pong
            break;
        default:
            LOG_ERR("Unknown opcode");
        }
    }

    void server::on_error(ws_session &s, const std::error_code &ec)
    {
        if (auto it = ws_routes.find(s.path); it != ws_routes.end())
            it->second.on_error_handler(s, ec);
        else
            LOG_WARN("No route for " + s.path);
    }

#ifdef ENABLE_CORS
    utils::u_ptr<response> server::cors(const request &req)
    {
        std::map<std::string, std::string> headers;
        headers["Access-Control-Allow-Origin"] = "*";
        headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
        headers["Access-Control-Allow-Headers"] = "*";
        headers["Access-Control-Max-Age"] = "86400";
        return utils::make_u_ptr<response>(status_code::ok, std::move(headers));
    }
#endif

#ifdef ENABLE_SSL
    std::string encode_password(const std::string &password, const std::string &salt)
    {
        int iterations = 10000;
        unsigned char hash[32];
        if (PKCS5_PBKDF2_HMAC(password.c_str(), password.size(), reinterpret_cast<const unsigned char *>(salt.c_str()), salt.size(), iterations, EVP_sha256(), sizeof(hash), hash) == 0)
            throw std::runtime_error("PKCS5_PBKDF2_HMAC failed");

        std::stringstream hash_stream;
        for (unsigned char c : hash)
            hash_stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        return hash_stream.str();
    }

    std::pair<std::string, std::string> encode_password(const std::string &password)
    {
        unsigned char salt[16];
        RAND_bytes(salt, sizeof(salt));
        std::stringstream salt_stream;
        for (unsigned char c : salt)
            salt_stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        return {salt_stream.str(), encode_password(password, salt_stream.str())};
    }
#endif
} // namespace network