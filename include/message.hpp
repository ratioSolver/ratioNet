#pragma once

#include <asio.hpp>

namespace network
{
  class ws_session;

  /**
   * @brief Represents a WebSocket message.
   */
  class message
  {
    friend class ws_session;

  public:
    /**
     * @brief Default constructor.
     */
    message() : fin_rsv_opcode(0x81), payload(std::make_shared<std::string>()) {}

    /**
     * @brief Constructor that sets the fin, rsv, and opcode of the message.
     *
     * @param fin_rsv_opcode The fin, rsv, and opcode of the message.
     */
    message(unsigned char fin_rsv_opcode) : fin_rsv_opcode(fin_rsv_opcode), payload(std::make_shared<std::string>()) {}

    /**
     * @brief Constructor that sets the payload of the message.
     *
     * @param payload The payload of the message.
     */
    message(std::shared_ptr<std::string> payload) : fin_rsv_opcode(0x81), payload(payload) {}

    /**
     * @brief Get the fin, rsv, and opcode of the message.
     *
     * @return The fin, rsv, and opcode of the message.
     */
    unsigned char get_fin_rsv_opcode() const noexcept { return fin_rsv_opcode; }

    /**
     * @brief Get the payload of the message.
     *
     * @return The payload of the message.
     */
    const std::string &get_payload() const noexcept { return *payload; }

    /**
     * @brief Get the buffer containing the serialized message.
     *
     * @return The buffer containing the serialized message.
     */
    asio::streambuf &get_buffer() noexcept
    {
      std::ostream os(&buffer);
      os.put(fin_rsv_opcode);
      if (payload->size() < 126)
        os.put(static_cast<unsigned char>(payload->size()));
      else if (payload->size() < 65536)
      {
        os.put(126);
        os.put((payload->size() >> 8) & 0xFF);
        os.put(payload->size() & 0xFF);
      }
      else
      {
        os.put(127);
        for (int i = 7; i >= 0; --i)
          os.put((payload->size() >> (8 * i)) & 0xFF);
      }
      os << *payload;
      return buffer;
    }

  private:
    unsigned char fin_rsv_opcode;         // fin, rsv, and opcode for the message
    asio::streambuf buffer;               // buffer for the message
    std::shared_ptr<std::string> payload; // payload of the message
  };
} // namespace network
