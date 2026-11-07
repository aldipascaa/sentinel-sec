#include <gtest/gtest.h>

#include <string>

#include "sentinel/result.hpp"

using namespace sentinel;

namespace {
Result<int> half(int v) {
    if (v % 2) return make_error("odd", Errc::InvalidArgument);
    return v / 2;
}
}  // namespace

TEST(Result, HoldsValue) {
    auto r = half(10);
    ASSERT_TRUE(r);
    EXPECT_EQ(r.value(), 5);
}

TEST(Result, HoldsError) {
    auto r = half(3);
    ASSERT_FALSE(r);
    EXPECT_EQ(r.error().message, "odd");
    EXPECT_EQ(r.error().code, Errc::InvalidArgument);
    EXPECT_THROW((void)r.value(), std::runtime_error);  // value() on an error throws at the boundary
}

TEST(Result, StringValueIsNotConfusedWithError) {
    Result<std::string> r = std::string("text");
    ASSERT_TRUE(r);
    EXPECT_EQ(r.value(), "text");
    Result<std::string> e = make_error("bad");
    EXPECT_FALSE(e);
}

TEST(Result, StatusHelpers) {
    EXPECT_TRUE(ok_status());
    Status s = make_error("nope");
    EXPECT_FALSE(s);
}
