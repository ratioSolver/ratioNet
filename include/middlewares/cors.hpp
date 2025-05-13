#include "middleware.hpp"
#include "memory.hpp"

namespace network
{
  class cors final : public middleware
  {
  public:
    cors(server &srv);

  private:
    void added_route(verb v, const route &r) override;

    utils::u_ptr<response> option_route(const request &req);
  };
} // namespace network
