#include "sentinel/password.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <vector>

namespace sentinel {
namespace {

std::string lower(std::string_view s) {
    std::string o(s);
    for (auto& c : o) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return o;
}

// Undo common leetspeak substitutions. `one_as_i` picks the reading of '1'.
std::string unleet(std::string_view s, bool one_as_i) {
    std::string o = lower(s);
    for (auto& c : o) {
        switch (c) {
            case '@': case '4': c = 'a'; break;
            case '3': c = 'e'; break;
            case '0': c = 'o'; break;
            case '$': case '5': c = 's'; break;
            case '7': c = 't'; break;
            case '!': c = 'i'; break;
            case '1': c = one_as_i ? 'i' : 'l'; break;
            default: break;
        }
    }
    return o;
}

bool in_list(const std::string& w, const std::unordered_set<std::string>* extra) {
    if (w.empty()) return false;
    if (builtin_wordlist().count(w)) return true;
    return extra && extra->count(w);
}

bool is_common(std::string_view pw, const std::unordered_set<std::string>* extra) {
    return in_list(lower(pw), extra) || in_list(unleet(pw, true), extra) || in_list(unleet(pw, false), extra);
}

bool is_alpha(char c) { return std::isalpha(static_cast<unsigned char>(c)) != 0; }

}  // namespace

std::string format_duration(double s) {
    char b[64];
    if (s < 1) return "instantly";
    if (s < 60) { std::snprintf(b, sizeof b, "%.0f seconds", s); return b; }
    if (s < 3600) { std::snprintf(b, sizeof b, "%.0f minutes", s / 60); return b; }
    if (s < 86400) { std::snprintf(b, sizeof b, "%.0f hours", s / 3600); return b; }
    if (s < 86400 * 365) { std::snprintf(b, sizeof b, "%.0f days", s / 86400); return b; }
    const double y = s / (86400.0 * 365);
    if (y < 1000) { std::snprintf(b, sizeof b, "%.0f years", y); return b; }
    if (y < 1e6) { std::snprintf(b, sizeof b, "%.0f thousand years", y / 1e3); return b; }
    return "millions of years or more";
}

PasswordResult audit_password(std::string_view pw, const std::unordered_set<std::string>* extra) {
    PasswordResult r;
    r.length = static_cast<int>(pw.size());
    if (pw.empty()) {
        r.label = "empty";
        r.crack_time = "instantly";
        r.feedback.push_back("Password is empty");
        return r;
    }

    bool lo = false, up = false, dg = false, sy = false, other = false;
    for (char ch : pw) {
        unsigned char c = static_cast<unsigned char>(ch);
        if (c >= 128) other = true;
        else if (std::islower(c)) lo = true;
        else if (std::isupper(c)) up = true;
        else if (std::isdigit(c)) dg = true;
        else sy = true;
    }
    int pool = (lo ? 26 : 0) + (up ? 26 : 0) + (dg ? 10 : 0) + (sy ? 33 : 0) + (other ? 100 : 0);
    const double per_char = std::log2(static_cast<double>(std::max(pool, 2)));
    r.raw_entropy_bits = per_char * r.length;

    // Mark characters that add (almost) no information: repeats, sequences, keyboard walks.
    const std::string low = lower(pw);
    const std::size_t n = low.size();
    std::vector<bool> redundant(n, false);
    auto mark = [&](std::size_t from, std::size_t len) {
        for (std::size_t i = from + 1; i < from + len; ++i) redundant[i] = true;
    };

    for (std::size_t i = 0; i < n;) {  // repeated characters
        std::size_t j = i;
        while (j < n && low[j] == low[i]) ++j;
        if (j - i >= 3) {
            mark(i, j - i);
            r.patterns.push_back("repeated character '" + std::string(1, low[i]) + "'");
        }
        i = j;
    }
    for (std::size_t i = 0; i + 1 < n;) {  // ascending / descending runs
        const int d = low[i + 1] - low[i];
        if ((d == 1 || d == -1) && (std::isalnum(static_cast<unsigned char>(low[i])) != 0)) {
            std::size_t j = i + 1;
            while (j + 1 < n && low[j + 1] - low[j] == d) ++j;
            if (j - i + 1 >= 4) {
                mark(i, j - i + 1);
                r.patterns.push_back(std::string(d > 0 ? "ascending" : "descending") + " sequence '" +
                                     low.substr(i, j - i + 1) + "'");
            }
            i = j;
        } else {
            ++i;
        }
    }
    static const char* rows[] = {"qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"};
    for (const char* row : rows) {  // keyboard walks (either direction)
        std::string fwd(row), rev(fwd.rbegin(), fwd.rend());
        for (const std::string* base : {&fwd, &rev}) {
            for (std::size_t len = base->size(); len >= 4; --len) {
                for (std::size_t s = 0; s + len <= base->size(); ++s) {
                    std::size_t pos = low.find(base->substr(s, len));
                    if (pos != std::string::npos && !redundant[pos + 1]) {
                        mark(pos, len);
                        r.patterns.push_back("keyboard pattern '" + base->substr(s, len) + "'");
                    }
                }
            }
        }
    }
    double eff_len = 0;
    for (bool b : redundant) eff_len += b ? 0.0 : 1.0;
    double bits = eff_len * per_char;

    // Trailing year like 1999 / 2024
    if (n >= 5) {
        const std::string tail = low.substr(n - 4);
        if ((tail.rfind("19", 0) == 0 || tail.rfind("20", 0) == 0) &&
            std::all_of(tail.begin(), tail.end(), [](char c) { return std::isdigit(static_cast<unsigned char>(c)) != 0; })) {
            bits -= 4 * per_char - 6.5;
            r.patterns.push_back("ends with a year");
        }
    }
    if (std::all_of(low.begin(), low.end(), [](char c) { return std::isdigit(static_cast<unsigned char>(c)) != 0; }))
        r.patterns.push_back("digits only");

    // Dictionary checks.
    const double dict_bits = std::log2(static_cast<double>(std::max<std::size_t>(builtin_wordlist().size(), 2)));
    if (is_common(pw, extra)) {
        r.common = true;
        bits = std::min(bits, dict_bits);
        r.patterns.push_back("appears in common-password list");
    } else {
        std::size_t end = n;
        while (end > 0 && !is_alpha(pw[end - 1])) --end;  // strip trailing digits/symbols
        if (end >= 4 && end < n) {
            if (is_common(pw.substr(0, end), extra)) {
                const double suffix_bits = static_cast<double>(n - end) * 3.5;
                bits = std::min(bits, dict_bits + suffix_bits + (std::isupper(static_cast<unsigned char>(pw[0])) ? 1.0 : 0.0));
                r.common = true;
                r.patterns.push_back("common word with appended digits/symbols");
            }
        }
    }
    r.entropy_bits = std::max(0.0, std::min(bits, r.raw_entropy_bits));

    // Score
    int score = r.entropy_bits < 28 ? 0 : r.entropy_bits < 36 ? 1 : r.entropy_bits < 60 ? 2 : r.entropy_bits < 80 ? 3 : 4;
    if (r.common) score = 0;
    if (r.length < 8) score = std::min(score, 1);
    r.score = score;
    static const char* labels[] = {"very weak", "weak", "fair", "good", "strong"};
    r.label = labels[score];

    const double secs = std::pow(2.0, std::min(r.entropy_bits, 200.0)) / 2.0 / 1e10;
    r.crack_time = format_duration(secs);

    // Feedback
    if (r.common) r.feedback.push_back("This is based on a commonly used password - pick something unique");
    if (r.length < 12) r.feedback.push_back("Use at least 12 characters (longer is better than complex)");
    if (!up || !lo) r.feedback.push_back("Mix upper- and lower-case letters");
    if (!dg) r.feedback.push_back("Add digits");
    if (!sy) r.feedback.push_back("Add a symbol such as ! or #");
    if (!r.patterns.empty() && !r.common) r.feedback.push_back("Avoid repeats, sequences and keyboard patterns");
    if (r.score >= 3 && r.feedback.empty()) r.feedback.push_back("Looks good - consider a password manager and unique passwords per site");
    if (r.score >= 3 && r.length >= 12 && !r.feedback.empty() && r.score == 4)
        r.feedback.insert(r.feedback.begin(), "Strong choice");
    return r;
}

std::unordered_set<std::string> load_wordlist(const std::string& path) {
    std::unordered_set<std::string> s;
    std::ifstream f(path);
    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        if (!line.empty()) s.insert(lower(line));
    }
    return s;
}

}  // namespace sentinel
