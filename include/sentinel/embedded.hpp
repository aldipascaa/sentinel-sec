#pragma once
#include <cstddef>

namespace sentinel {

// A file compiled into the binary by cmake/embed.cmake.
struct EmbeddedAsset {
    const char* name;  // file name, e.g. "app.js"
    const char* mime;
    const unsigned char* data;
    std::size_t size;
};

// Defined in generated sources (see CMakeLists.txt).
extern const EmbeddedAsset kRulesAssets[];
extern const std::size_t kRulesAssetsCount;
extern const EmbeddedAsset kWebAssets[];
extern const std::size_t kWebAssetsCount;

}  // namespace sentinel
