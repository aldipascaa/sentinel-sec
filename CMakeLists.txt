cmake_minimum_required(VERSION 3.20)
project(Sentinel VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

option(SENTINEL_BUILD_TESTS "Build unit tests" ON)

include(FetchContent)
set(FETCHCONTENT_QUIET ON)

# Header-only deps: populate only (SOURCE_SUBDIR points at nothing, so no add_subdirectory).
FetchContent_Declare(nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.12.0 GIT_SHALLOW TRUE SOURCE_SUBDIR _no_cmake)
FetchContent_Declare(httplib
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG v0.20.1 GIT_SHALLOW TRUE SOURCE_SUBDIR _no_cmake)
FetchContent_MakeAvailable(nlohmann_json httplib)

if(SENTINEL_BUILD_TESTS)
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2 GIT_SHALLOW TRUE)
  FetchContent_MakeAvailable(googletest)
endif()

# ---- generated files: version header + embedded dashboard ----
set(GEN_DIR ${CMAKE_BINARY_DIR}/generated)
configure_file(cmake/version.hpp.in ${GEN_DIR}/sentinel/version.hpp @ONLY)
include(cmake/embed.cmake)
sentinel_embed(${CMAKE_SOURCE_DIR}/web/index.html ${GEN_DIR}/web_assets.cpp kIndexHtml)

# ---- core library ----
add_library(sentinel_core STATIC
  src/portrange.cpp src/services.cpp src/scanner.cpp
  src/logscan.cpp src/password.cpp src/wordlist.cpp src/report.cpp)
target_include_directories(sentinel_core PUBLIC include ${GEN_DIR})
target_include_directories(sentinel_core SYSTEM PUBLIC ${nlohmann_json_SOURCE_DIR}/include)
target_link_libraries(sentinel_core PUBLIC ws2_32)
target_compile_definitions(sentinel_core PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00)

add_executable(sentinel src/main.cpp src/server.cpp ${GEN_DIR}/web_assets.cpp)
target_include_directories(sentinel PRIVATE src)
target_include_directories(sentinel SYSTEM PRIVATE ${httplib_SOURCE_DIR})
target_link_libraries(sentinel PRIVATE sentinel_core)

if(MSVC)
  foreach(t sentinel_core sentinel)
    target_compile_options(${t} PRIVATE /W4 /WX /utf-8 /permissive-)
  endforeach()
endif()

if(SENTINEL_BUILD_TESTS)
  enable_testing()
  add_executable(sentinel_tests tests/test_portrange.cpp tests/test_logscan.cpp
                 tests/test_password.cpp tests/test_scanner.cpp)
  target_link_libraries(sentinel_tests PRIVATE sentinel_core GTest::gtest_main)
  if(MSVC)
    target_compile_options(sentinel_tests PRIVATE /W4 /WX /utf-8 /permissive-)
  endif()
  include(GoogleTest)
  gtest_discover_tests(sentinel_tests DISCOVERY_MODE PRE_TEST)
endif()
