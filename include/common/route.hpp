#pragma once

#include <functional>
#include <memory>
#include <regex>
#include <set>

namespace network
{
  class request;
  class response;

  /**
   * @brief Represents a route in the server.
   */
  class route
  {
  public:
    route(std::string_view pattern, const std::function<std::unique_ptr<response>(request &)> &&handler) noexcept : pattern(pattern), path(pattern.data()), handler(std::move(handler)) {}

    /**
     * @brief Retrieves the pattern associated with the route.
     *
     * This function provides access to the pattern string, which is used
     * to define the route's matching criteria.
     *
     * @return A constant reference to the pattern string.
     */
    [[nodiscard]] const std::string &get_pattern() const noexcept { return pattern; }

    /**
     * @brief Retrieves the path of the route.
     *
     * This function returns a constant reference to a std::regex object that represents
     * the path of the route.
     *
     * @return A constant reference to the path regex.
     */
    [[nodiscard]] const std::regex &get_path() const noexcept { return path; }

    /**
     * @brief Checks if the given path matches the route's pattern.
     *
     * This function checks if the provided path string matches the route's pattern
     * using regular expression matching.
     *
     * @param path The path string to check for a match.
     * @return true if the path matches the route's pattern, false otherwise.
     */
    [[nodiscard]] bool match(const std::string &path) const noexcept
    {
      std::smatch match;
      return std::regex_match(path, match, this->path);
    }

    /**
     * @brief Retrieves the handler function for processing requests.
     *
     * This function returns a constant reference to a std::function that takes a
     * reference to a request object and returns a unique pointer to a response object.
     *
     * @return A constant reference to the handler function.
     */
    [[nodiscard]] const std::function<std::unique_ptr<response>(request &)> &get_handler() const noexcept { return handler; }

  private:
    const std::string pattern;                                         // pattern of the route
    const std::regex path;                                             // path of the route
    const std::function<std::unique_ptr<response>(request &)> handler; // handler function for the route
  };
} // namespace network
