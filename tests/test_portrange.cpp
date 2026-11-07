#include <gtest/gtest.h>

#include "sentinel/portrange.hpp"

using namespace sentinel;

TEST(PortRange, SinglePort) {
    EXPECT_EQ(parse_port_ranges("80"), (std::vector<std::uint16_t>{80}));
}

TEST(PortRange, RangeAndList) {
    EXPECT_EQ(parse_port_ranges("22, 80,8000-8002"), (std::vector<std::uint16_t>{22, 80, 8000, 8001, 8002}));
}

TEST(PortRange, SortedAndDeduplicated) {
    EXPECT_EQ(parse_port_ranges("443,80,80,79-81"), (std::vector<std::uint16_t>{79, 80, 81, 443}));
}

TEST(PortRange, FullRange) {
    EXPECT_EQ(parse_port_ranges("1-65535").size(), 65535u);
}

TEST(PortRange, CommonKeyword) {
    auto v = parse_port_ranges("common");
    EXPECT_FALSE(v.empty());
    EXPECT_NE(std::find(v.begin(), v.end(), 22), v.end());
    EXPECT_NE(std::find(v.begin(), v.end(), 443), v.end());
}

TEST(PortRange, RejectsInvalid) {
    EXPECT_THROW(parse_port_ranges(""), std::invalid_argument);
    EXPECT_THROW(parse_port_ranges("0"), std::invalid_argument);
    EXPECT_THROW(parse_port_ranges("65536"), std::invalid_argument);
    EXPECT_THROW(parse_port_ranges("abc"), std::invalid_argument);
    EXPECT_THROW(parse_port_ranges("100-50"), std::invalid_argument);
    EXPECT_THROW(parse_port_ranges("80,,90"), std::invalid_argument);
    EXPECT_THROW(parse_port_ranges("-5"), std::invalid_argument);
    EXPECT_THROW(parse_port_ranges("1-2-3"), std::invalid_argument);
}

TEST(PortRange, ServiceNames) {
    EXPECT_EQ(service_name(22), "ssh");
    EXPECT_EQ(service_name(443), "https");
    EXPECT_EQ(service_name(54321), "");
}
