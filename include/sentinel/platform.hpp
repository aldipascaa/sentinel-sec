#pragma once
// Thin portability helpers (thread-safe time conversion, tty detection).
#include <cstdio>
#include <ctime>

namespace sentinel::platform {

std::tm utc_tm(std::time_t t);
std::tm local_tm(std::time_t t);
bool is_tty(std::FILE* f);

}  // namespace sentinel::platform
