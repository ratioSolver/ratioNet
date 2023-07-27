#pragma once

#include "memory.h"
#include <string>

namespace network
{
  class message final : public utils::countable
  {
  public:
    message(const std::string &msg) : msg(msg) {}
    message(const std::string &&msg) : msg(std::move(msg)) {}

    const std::string &get() const { return msg; }

  private:
    std::string msg;
  };

  using message_ptr = utils::c_ptr<message>;
} // namespace network
