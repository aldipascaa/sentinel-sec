#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace sentinel {

// Parses "80", "1-1024", "22,80,8000-8010" or the keyword "common".
// Result is sorted and de-duplicated. Throws std::invalid_argument on bad input.
std::vector<std::uint16_t> parse_port_ranges(const std::string& spec);

// Ports of well-known services, used for the "common" keyword.
std::vector<std::uint16_t> common_ports();

// Best-effort service name for a port ("" when unknown).
std::string service_name(std::uint16_t port);

}  // namespace sentinel
