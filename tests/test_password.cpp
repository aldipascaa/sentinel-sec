#include <gtest/gtest.h>

#include "sentinel/password.hpp"

using namespace sentinel;

TEST(Password, EmptyIsHandled) {
    auto r = audit_password("");
    EXPECT_EQ(r.score, 0);
    EXPECT_EQ(r.length, 0);
}

TEST(Password, CommonPasswordsAreVeryWeak) {
    for (const char* p : {"password", "123456", "qwerty", "Password", "letmein"}) {
        auto r = audit_password(p);
        EXPECT_TRUE(r.common) << p;
        EXPECT_EQ(r.score, 0) << p;
    }
}

TEST(Password, LeetspeakOfCommonIsCaught) {
    EXPECT_TRUE(audit_password("P@ssw0rd").common);
    EXPECT_TRUE(audit_password("dr4gon").common);
}

TEST(Password, CommonWordWithSuffixIsWeak) {
    auto r = audit_password("Dragon2024!");
    EXPECT_TRUE(r.common);
    EXPECT_LE(r.score, 1);
}

TEST(Password, EntropyGrowsWithLengthAndVariety) {
    auto a = audit_password("kqzvxm");
    auto b = audit_password("kqzvxmwj");
    auto c = audit_password("kQzv8mW!");
    EXPECT_LT(a.entropy_bits, b.entropy_bits);
    EXPECT_LT(b.entropy_bits, c.entropy_bits);
    EXPECT_NEAR(b.raw_entropy_bits, 8 * 4.70, 0.1);  // 8 * log2(26)
}

TEST(Password, ShortPasswordsCapAtWeak) {
    EXPECT_LE(audit_password("aZ9!x#Q").score, 1);
}

TEST(Password, RandomLongPasswordIsStrong) {
    auto r = audit_password("vT7#mQ2$zL9&kR4!wX8");
    EXPECT_EQ(r.score, 4);
    EXPECT_FALSE(r.common);
}

TEST(Password, LongPassphraseIsGood) {
    EXPECT_GE(audit_password("correct horse battery staple 42").score, 3);
}

TEST(Password, PatternsReduceEntropy) {
    auto rep = audit_password("aaaaaaaaaaaa");
    EXPECT_LT(rep.entropy_bits, rep.raw_entropy_bits / 4);
    EXPECT_FALSE(rep.patterns.empty());
    auto seq = audit_password("abcdefgh");
    EXPECT_LT(seq.entropy_bits, seq.raw_entropy_bits / 2);
    auto kb = audit_password("zxcvbnm,./");
    EXPECT_LT(kb.entropy_bits, kb.raw_entropy_bits);
}

TEST(Password, YearSuffixIsPenalised) {
    auto with = audit_password("Hq8xKmzp1987");
    auto without = audit_password("Hq8xKmzp4172");
    EXPECT_LT(with.entropy_bits, without.entropy_bits);
}

TEST(Password, ExtraWordlistIsUsed) {
    std::unordered_set<std::string> extra = {"companyname"};
    EXPECT_FALSE(audit_password("CompanyName").common);
    EXPECT_TRUE(audit_password("CompanyName", &extra).common);
}

TEST(Password, FeedbackAndCrackTime) {
    auto r = audit_password("abc");
    EXPECT_FALSE(r.feedback.empty());
    EXPECT_EQ(r.crack_time, "instantly");
    EXPECT_NE(audit_password("vT7#mQ2$zL9&kR4!wX8").crack_time, "instantly");
}

TEST(Password, FormatDuration) {
    EXPECT_EQ(format_duration(0.1), "instantly");
    EXPECT_EQ(format_duration(120), "2 minutes");
    EXPECT_EQ(format_duration(86400 * 3), "3 days");
}

TEST(Password, BuiltinWordlistIsPopulatedAndLowercase) {
    EXPECT_GT(builtin_wordlist().size(), 100u);
    for (auto& w : builtin_wordlist())
        for (char c : w) EXPECT_FALSE(c >= 'A' && c <= 'Z') << w;
}
