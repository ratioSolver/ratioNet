#pragma once

#include "verb.hpp"

namespace network
{
  class route;
  class request;
  class response;
  class server;

  class middleware
  {
    friend class server;

  public:
    middleware(server &srv) : srv(srv) {}
    virtual ~middleware() = default;

  private:
    virtual void added_route(verb, const route &) {}

    virtual void before_request(const request &) {}
    virtual void after_request(const request &, response &) {}

  protected:
    server &srv;
  };
} // namespace network
