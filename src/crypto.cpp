#include <boost/compute/detail/sha1.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include "crypto.hpp"

namespace network
{
    std::string sha1(const std::string &input) { return static_cast<std::string>(boost::compute::detail::sha1(input)); }

    std::string base64_encode(const std::string &input)
    {
        using namespace boost::archive::iterators;
        using It = base64_from_binary<transform_width<std::string::const_iterator, 6, 8>>;
        auto tmp = std::string(It(std::begin(input)), It(std::end(input)));
        return tmp.append((3 - input.size() % 3) % 3, '=');
    }
} // namespace network
