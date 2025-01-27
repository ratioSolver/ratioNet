#pragma once

#include "memory.hpp"
#include <regex>
#include <functional>
#include <set>

namespace network
{
  class request;
  class response;

  /**
   * @brief Represents a route in the server.
   *
   * This class represents a route in the server. A route consists of a path and a handler function.
   */
  class route
  {
  public:
    /**
     * @brief Constructs a route object with the specified path and handler function.
     *
     * @param path A regular expression representing the path for the route.
     * @param handler A function that takes a request reference and returns a unique pointer to a response.
     */
    route(const std::regex &path, std::function<utils::u_ptr<response>(request &)> &&handler) noexcept : path(path), handler(std::move(handler)) {}

    /**
     * @brief Retrieves the path as a constant reference to a regex object.
     *
     * This function returns a constant reference to the regex object representing the path.
     * It is marked as noexcept, indicating that it does not throw any exceptions.
     *
     * @return const std::regex& A constant reference to the regex object representing the path.
     */
    const std::regex &get_path() const noexcept { return path; }

    /**
     * @brief Retrieves the handler function for processing requests.
     *
     * This function returns a constant reference to a std::function that takes a
     * reference to a request object and returns a unique pointer to a response object.
     *
     * @return A constant reference to the handler function.
     */
    const std::function<utils::u_ptr<response>(request &)> &get_handler() const noexcept { return handler; }

  private:
    std::regex path;                                          // path of the route
    std::function<utils::u_ptr<response>(request &)> handler; // handler function for the route
  };
} // namespace network
