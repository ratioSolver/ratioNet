#include "middleware.hpp"
#include <memory>

namespace network
{
  class log final : public middleware
  {
  public:
    log(server_base &srv);

  private:
    virtual std::unique_ptr<response> before_request(const request &req) override;
    void after_request(const request &req, response &res) override;
  };
} // namespace network
