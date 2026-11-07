#include "sentinel/portrange.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace sentinel {
namespace {

std::string trim(const std::string& s) {
    std::size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

unsigned parse_port(const std::string& tok, const std::string& whole) {
    if (tok.empty() || tok.size() > 5 ||
        !std::all_of(tok.begin(), tok.end(), [](char c) { return c >= '0' && c <= '9'; }))
        throw std::invalid_argument("invalid port '" + tok + "' in '" + whole + "'");
    unsigned v = static_cast<unsigned>(std::stoul(tok));
    if (v < 1 || v > 65535) throw std::invalid_argument("port out of range 1-65535: " + tok);
    return v;
}

}  // namespace

std::vector<std::uint16_t> parse_port_ranges(const std::string& spec) {
    if (trim(spec).empty()) throw std::invalid_argument("empty port specification");
    std::vector<std::uint16_t> out;
    std::size_t start = 0;
    while (start <= spec.size()) {
        std::size_t comma = spec.find(',', start);
        if (comma == std::string::npos) comma = spec.size();
        const std::string tok = trim(spec.substr(start, comma - start));
        if (tok.empty()) throw std::invalid_argument("empty entry in port list '" + spec + "'");
        if (tok == "common") {
            auto c = common_ports();
            out.insert(out.end(), c.begin(), c.end());
        } else if (auto dash = tok.find('-'); dash != std::string::npos) {
            unsigned lo = parse_port(trim(tok.substr(0, dash)), tok);
            unsigned hi = parse_port(trim(tok.substr(dash + 1)), tok);
            if (lo > hi) throw std::invalid_argument("descending port range '" + tok + "'");
            for (unsigned p = lo; p <= hi; ++p) out.push_back(static_cast<std::uint16_t>(p));
        } else {
            out.push_back(static_cast<std::uint16_t>(parse_port(tok, spec)));
        }
        start = comma + 1;
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

}  // namespace sentinel
