#pragma once

#include <string>

namespace network
{
  /**
   * Calculates the SHA-1 hash of the given input string.
   *
   * @param input The input string to calculate the hash for.
   * @return The SHA-1 hash of the input string.
   */
  std::string sha1(const std::string &input);

  /**
   * Encodes a given input string into base64 format.
   *
   * @param input The input string to be encoded.
   * @return The base64 encoded string.
   */
  std::string base64_encode(const std::string &input);
} // namespace network