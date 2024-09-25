#pragma once

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
   * This class represents a route in the server. A route consists of a path, a handler function, and a set of roles that are allowed to access the route.
   */
  class route
  {
  public:
    /**
     * @brief Constructs a route object with the specified path, handler, and roles.
     *
     * @param path A regular expression representing the path for the route.
     * @param handler A function that takes a request reference and returns a unique pointer to a response.
     * @param roles A set of integers representing roles that are allowed to access this route. Defaults to an empty set.
     */
    route(const std::regex &path, std::function<std::unique_ptr<response>(request &)> &&handler, const std::set<int> &roles = {}) noexcept : path(path), handler(std::move(handler)), roles(roles) {}

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
    const std::function<std::unique_ptr<response>(request &)> &get_handler() const noexcept { return handler; }

    /**
     * @brief Retrieves the set of roles.
     *
     * This function returns a constant reference to a set containing role identifiers.
     *
     * @return const std::set<int>& A constant reference to the set of roles.
     */
    const std::set<int> &get_roles() const noexcept { return roles; }

  private:
    std::regex path;                                             // path of the route
    std::function<std::unique_ptr<response>(request &)> handler; // handler function for the route
    std::set<int> roles;                                         // roles that have permission to access the route
  };
} // namespace network
