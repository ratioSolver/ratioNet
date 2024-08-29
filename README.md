# ratioNet

![Build Status](https://github.com/ratioSolver/ratioNet/actions/workflows/cmake.yml/badge.svg)

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

**Install [Boost](https://www.boost.org)**
The framework relies on the Boost library for managing data structures and algorithms. You can install Boost on your local machine using the following command:

```bash
sudo apt-get install libboost-all-dev
```

Clone the Repository: Start by cloning this repository to your local machine:

```bash
git clone https://github.com/ratioSolver/ratioNet.git
```

## Usage

Here's a simple example of how to use `ratioNet` to create an HTTP server:

```cpp
#include <server.hpp>

int main()
{
    // Create the server instance
    network::server server;

    // Add a GET route to the server
    server.add_route(network::verb::Get, "/", [](network::request &req) { return std::make_unique<network::html_response>("<html><body><h1>Hello, World!</h1></body></html>"); });

    // Add a WebSocket route to the server
    server.add_ws_route("/ws").on_open([](network::ws_session &s) { s.send("Hello, World!"); })
                              .on_message([](network::ws_session &s, const std::string &msg) { s.send(msg); });

    // Start the server
    server.start();

    return 0;
}
```

Creating a client is just as easy:

```cpp
#include <client.hpp>

int main()
{
    // Create the client instance
    network::client client;

    // Send an HTTP request
    auto res = client.get("/");

    // Print the response
    std::cout << res << std::endl;

    return 0;
}
```

## Contributing
Contributions to the framework are welcome! If you find any bugs, have feature requests, or would like to contribute in any way, please submit issues and pull requests to the GitHub repository.
