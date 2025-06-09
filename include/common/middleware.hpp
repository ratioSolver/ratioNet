#pragma once

#include "verb.hpp"

namespace network
{
  class route;
  class request;
  class response;
  class server_base;

  class middleware
  {
    friend class server_base;

  public:
    middleware(server_base &srv) : srv(srv) {}
    virtual ~middleware() = default;

  private:
    virtual void added_route(verb, const route &) {}

    virtual void before_request(const request &) {}
    virtual void after_request(const request &, response &) {}

  protected:
    server_base &srv;
  };
} // namespace network
