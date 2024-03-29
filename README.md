# ratioNet

Welcome to the `ratioNet` documentation. This framework provides a powerful and flexible foundation for building networked applications using the [Boost.Beast](https://github.com/boostorg/beast) library. Whether you're developing a web server, a WebSocket application, or any other networked software, this framework will help you get started quickly and efficiently.

## Features

- **Boost.Beast Integration**: The framework is built on top of the Boost.Beast library, providing seamless integration and access to its powerful networking capabilities.

- **Asynchronous Design**: All network operations are designed to be asynchronous, allowing your application to handle multiple connections concurrently without blocking.

- **Customizable**: The framework is designed to be modular and customizable. You can easily extend and adapt it to your specific use cases and requirements.

- **HTTP and WebSocket Support**: The framework includes modules to handle HTTP and WebSocket protocols, making it suitable for building web servers, APIs, and real-time applications.

- **Thread Safety**: The framework is designed with thread safety in mind, allowing you to build robust multi-threaded networked applications.

- **Examples and Tutorials**: The repository includes examples and tutorials to help you understand how to use the framework effectively in different scenarios.

## Getting Started
Follow these steps to get started with `ratioNet`:

Clone the Repository: Start by cloning this repository to your local machine:

```bash
git clone https://github.com/ratioSolver/ratioNet.git
```

## Usage

Here's a simple example of how to use `ratioNet` to create an HTTP server:

```cpp
#include <server.hpp>

using string_req = boost::beast::http::request<boost::beast::http::string_body>;
using string_res = boost::beast::http::response<boost::beast::http::string_body>;

int main()
{
    // Create the server instance
    network::server server;

    // Add a GET route to the server
    server.add_route(boost::beast::http::verb::get, "/", std::function{[](const string_req &, string_res &res)
    {
        res.set(boost::beast::http::field::content_type, "html");
        res.body() = R"(<html><body><h1>Hello, world!</h1></body></html>)";
    }});

    // Add a WebSocket route to the server
    server.add_ws_route("/ws").on_open([](network::websocket_session &session)
    { session.send("Hello, world!"); });

    // Start the server
    server.start();

    return 0;
}
```

Creating a REST client is just as easy:

```cpp
#include <client.hpp>

using string_res = boost::beast::http::response<boost::beast::http::string_body>;

int main()
{
    // Create the client instance
    network::plain_client client("localhost", "8080", []() { std::cout << "Connected!" << std::endl; });

    // Send a GET request to the server
    auto res = client.get("/", std::function{[](const string_res &res, boost::beast::error_code ec)
    {
        if (ec)
            std::cout << "Error: " << ec.message() << std::endl;
        else
            std::cout << res.body() << std::endl;
    }});

    return 0;
}
```

Finally, here's an example of how to create a WebSocket client:

```cpp
#include <ws_client.hpp>

int main()
{
    // Create the client instance
    network::plain_ws_client client("localhost", "8080", "/ws",
        []() { std::cout << "Connected!" << std::endl; },
        [](const std::string &msg) { std::cout << "Received: " << msg << std::endl; });

    // Send a message to the server
    client.send("Hello, world!");

    return 0;
}
```

## Contributing
Contributions to the framework are welcome! If you find any bugs, have feature requests, or would like to contribute in any way, please submit issues and pull requests to the GitHub repository.
