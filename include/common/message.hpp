#pragma once

#include <asio.hpp>
#include <random>

namespace network
{
  class ws_server_session_base;
  class ws_client_session_base;

  /**
   * @brief Represents a WebSocket message.
   */
  class message
  {
    friend class ws_server_session_base;
    friend class ws_client_session_base;

  public:
    /**
     * @brief Constructor that sets the fin, rsv, and opcode of the message.
     *
     * @param fin_rsv_opcode The fin, rsv, and opcode of the message.
     */
    message(unsigned char fin_rsv_opcode = 0x81, bool masked = false) : masked(masked), fin_rsv_opcode(fin_rsv_opcode), payload(std::make_shared<std::string>()) {}

    /**
     * @brief Constructor that sets the payload of the message.
     *
     * @param payload The payload of the message.
     */
    message(std::shared_ptr<std::string> payload, bool masked = false) : masked(masked), fin_rsv_opcode(0x81), payload(payload) {}

    /**
     * @brief Checks if the message is marked as final.
     *
     * This function determines whether the FIN (final) bit is set in the
     * fin_rsv_opcode member, indicating that this is the final fragment
     * in a message sequence (e.g., in WebSocket frames).
     *
     * @return true if the FIN bit is set (message is final), false otherwise.
     */
    [[nodiscard]] bool is_final() const noexcept { return (fin_rsv_opcode & 0x80) != 0; }

    /**
     * @brief Get the opcode of the message.
     *
     * The opcode is extracted from the fin_rsv_opcode member, which contains
     * the FIN, RSV, and opcode bits. The opcode is represented by the lower
     * 4 bits of this byte.
     *
     * @return The opcode of the message.
     */
    [[nodiscard]] uint8_t get_opcode() const noexcept { return fin_rsv_opcode & 0x0F; }

    /**
     * @brief Checks if the message is a continuation frame.
     *
     * This function determines whether the current message's opcode
     * indicates a continuation frame (opcode 0x00), which is typically
     * used in protocols like WebSocket to signify that the message is
     * a continuation of a previous fragmented message.
     *
     * @return true if the message is a continuation frame, false otherwise.
     */
    [[nodiscard]] bool is_continuation() const noexcept { return get_opcode() == 0x00; }
    /**
     * @brief Checks if the message is a text frame.
     *
     * This function checks if the opcode of the message indicates that it
     * is a text frame (opcode 0x01), which is commonly used in protocols
     * like WebSocket to represent text data.
     *
     * @return true if the message is a text frame, false otherwise.
     */
    [[nodiscard]] bool is_text() const noexcept { return get_opcode() == 0x01; }
    /**
     * @brief Checks if the message is a binary frame.
     *
     * This function checks if the opcode of the message indicates that it
     * is a binary frame (opcode 0x02), which is commonly used in protocols
     * like WebSocket to represent binary data.
     *
     * @return true if the message is a binary frame, false otherwise.
     */
    [[nodiscard]] bool is_binary() const noexcept { return get_opcode() == 0x02; }

    /**
     * @brief Checks if the message is a close frame.
     *
     * This function checks if the opcode of the message indicates that it
     * is a close frame (opcode 0x08), which is used in protocols like WebSocket
     * to indicate that the connection should be closed.
     *
     * @return true if the message is a close frame, false otherwise.
     */
    [[nodiscard]] bool is_close() const noexcept { return get_opcode() == 0x08; }
    /**
     * @brief Checks if the message is a ping frame.
     *
     * This function checks if the opcode of the message indicates that it
     * is a ping frame (opcode 0x09), which is used in protocols like WebSocket
     * to check the connection status.
     *
     * @return true if the message is a ping frame, false otherwise.
     */
    [[nodiscard]] bool is_ping() const noexcept { return get_opcode() == 0x09; }
    /**
     * @brief Checks if the message is a pong frame.
     *
     * This function checks if the opcode of the message indicates that it
     * is a pong frame (opcode 0x0A), which is used in protocols like WebSocket
     * to respond to a ping frame.
     *
     * @return true if the message is a pong frame, false otherwise.
     */
    [[nodiscard]] bool is_pong() const noexcept { return get_opcode() == 0x0A; }

    /**
     * @brief Get the fin, rsv, and opcode of the message.
     *
     * @return The fin, rsv, and opcode of the message.
     */
    [[nodiscard]] uint8_t get_fin_rsv_opcode() const noexcept { return fin_rsv_opcode; }

    /**
     * @brief Get the payload of the message.
     *
     * @return The payload of the message.
     */
    [[nodiscard]] const std::string &get_payload() const noexcept { return *payload; }

  private:
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

      if (masked)
      { // Create mask
        std::array<unsigned char, 4> mask;
        std::uniform_int_distribution<unsigned short> dist(0, 255);
        std::random_device rd;
        for (std::size_t c = 0; c < 4; c++)
          mask[c] = static_cast<unsigned char>(dist(rd));

        // Write mask to buffer
        for (std::size_t c = 0; c < 4; c++)
          os.put(mask[c]);

        // Write masked payload to buffer
        for (std::size_t c = 0; c < payload->size(); c++)
          os.put((*payload)[c] ^ mask[c % 4]);
      }
      else // Write payload to buffer
        os << *payload;
      return buffer;
    }

  private:
    const bool masked = true;             // whether the message is masked
    uint8_t fin_rsv_opcode;               // fin, rsv, and opcode for the message
    asio::streambuf buffer;               // buffer for the message
    std::shared_ptr<std::string> payload; // payload of the message
  };
} // namespace network
