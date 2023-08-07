#include "server.h"

namespace network
{
    server::server(const std::string &address, unsigned short port, std::size_t thread_pool_size) : thread_pool_size(thread_pool_size), ioc(thread_pool_size), signals(ioc), acceptor(ioc)
    {
        signals.add(SIGINT);
        signals.add(SIGTERM);
#if defined(SIGQUIT)
        signals.add(SIGQUIT);
#endif // defined(SIGQUIT)

        signals.async_wait([this](boost::system::error_code, int)
                           { stop(); });

        boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::make_address(address), port);
    }

    void server::start()
    {
        for (std::size_t i = 0; i < thread_pool_size; ++i)
            threads.emplace_back([this]
                                 { ioc.run(); });
        ioc.run();
    }

    void server::stop()
    {
        ioc.stop();

        for (auto &thread : threads)
            thread.join();
    }
} // namespace network
