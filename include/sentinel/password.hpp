#pragma once
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace sentinel {

struct PasswordResult {
    int length = 0;
    double entropy_bits = 0;      // after pattern penalties
    double raw_entropy_bits = 0;  // naive length * log2(charset)
    int score = 0;                // 0 (very weak) .. 4 (strong)
    std::string label;
    bool common = false;
    std::vector<std::string> patterns;
    std::vector<std::string> feedback;
    std::string crack_time;  // offline fast-hash attack estimate (1e10 guesses/s)
};

// Built-in list of very common passwords (lower-case).
const std::unordered_set<std::string>& builtin_wordlist();
// Loads one word per line; lower-cased. Returns empty set if the file cannot be opened.
std::unordered_set<std::string> load_wordlist(const std::string& path);

// Evaluates a candidate. The password is never stored or logged by this function.
// `extra` is an optional additional wordlist.
PasswordResult audit_password(std::string_view pw, const std::unordered_set<std::string>* extra = nullptr);

std::string format_duration(double seconds);

}  // namespace sentinel
