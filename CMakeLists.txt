cmake_minimum_required(VERSION 3.21)
project(Sentinel VERSION 1.2.1 LANGUAGES CXX
        DESCRIPTION "Defensive security toolkit: port scanner, log anomaly detector, password auditor")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)  # for older third-party CMake projects (googletest)

if(PROJECT_IS_TOP_LEVEL)
  set(_sentinel_top ON)
else()
  set(_sentinel_top OFF)
endif()
option(SENTINEL_BUILD_TESTS  "Build unit tests"                         ${_sentinel_top})
option(SENTINEL_BUILD_SERVER "Build the dashboard server (cpp-httplib)" ON)
option(SENTINEL_INSTALL      "Generate install rules"                   ${_sentinel_top})

include(GNUInstallDirs)
include(FetchContent)
set(FETCHCONTENT_QUIET ON)

# Header-only deps: populate only (SOURCE_SUBDIR points at nothing, so no add_subdirectory).
FetchContent_Declare(nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.12.0 GIT_SHALLOW TRUE SOURCE_SUBDIR _no_cmake)
FetchContent_MakeAvailable(nlohmann_json)
if(SENTINEL_BUILD_SERVER)
  FetchContent_Declare(httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.20.1 GIT_SHALLOW TRUE SOURCE_SUBDIR _no_cmake)
  FetchContent_MakeAvailable(httplib)
endif()
if(SENTINEL_BUILD_TESTS)
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2 GIT_SHALLOW TRUE)
  FetchContent_MakeAvailable(googletest)
endif()

find_package(Threads REQUIRED)

# ---- warnings: one interface target, linked privately by every Sentinel target ----
add_library(sentinel_warnings INTERFACE)
target_compile_options(sentinel_warnings INTERFACE
  $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX /utf-8 /permissive->
  $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic -Werror>)
add_library(sentinel::warnings ALIAS sentinel_warnings)

# ---- generated files: version header + embedded assets ----
set(GEN_DIR ${CMAKE_BINARY_DIR}/generated)
configure_file(cmake/version.hpp.in ${GEN_DIR}/sentinel/version.hpp @ONLY)
include(cmake/embed.cmake)
sentinel_embed(${GEN_DIR}/rules_assets.cpp kRulesAssets
  "${CMAKE_SOURCE_DIR}/rules/default_rules.json|application/json")
sentinel_embed(${GEN_DIR}/web_assets.cpp kWebAssets
  "${CMAKE_SOURCE_DIR}/web/index.html|text/html"
  "${CMAKE_SOURCE_DIR}/web/app.css|text/css"
  "${CMAKE_SOURCE_DIR}/web/app.js|application/javascript")

set(_win_defs $<$<PLATFORM_ID:Windows>:NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00>)

# ---- core library: no HTTP, no CLI ----
add_library(sentinel_core STATIC
  src/net_socket.cpp src/platform.cpp
  src/portrange.cpp src/services.cpp src/scanner.cpp
  src/logscan.cpp src/rules.cpp src/password.cpp src/wordlist.cpp src/report.cpp
  ${GEN_DIR}/rules_assets.cpp)
add_library(sentinel::core ALIAS sentinel_core)
set_target_properties(sentinel_core PROPERTIES EXPORT_NAME core)
target_compile_features(sentinel_core PUBLIC cxx_std_20)
target_include_directories(sentinel_core PUBLIC
  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${GEN_DIR}>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_include_directories(sentinel_core SYSTEM PUBLIC $<BUILD_INTERFACE:${nlohmann_json_SOURCE_DIR}/include>)
target_link_libraries(sentinel_core
  PUBLIC  Threads::Threads $<$<PLATFORM_ID:Windows>:ws2_32>
  PRIVATE $<BUILD_INTERFACE:sentinel_warnings>)
target_compile_definitions(sentinel_core PRIVATE ${_win_defs})

# ---- dashboard server library (HTTP lives here, never in core) ----
if(SENTINEL_BUILD_SERVER)
  add_library(sentinel_server STATIC src/server.cpp ${GEN_DIR}/web_assets.cpp)
  add_library(sentinel::server ALIAS sentinel_server)
  set_target_properties(sentinel_server PROPERTIES EXPORT_NAME server)
  target_include_directories(sentinel_server SYSTEM PRIVATE ${httplib_SOURCE_DIR})
  target_link_libraries(sentinel_server
    PUBLIC  sentinel_core
    PRIVATE $<BUILD_INTERFACE:sentinel_warnings>)
  target_compile_definitions(sentinel_server PRIVATE ${_win_defs})
endif()

# ---- CLI ----
add_executable(sentinel src/main.cpp)
target_link_libraries(sentinel PRIVATE sentinel_core $<BUILD_INTERFACE:sentinel_warnings>)
if(SENTINEL_BUILD_SERVER)
  target_link_libraries(sentinel PRIVATE sentinel_server)
  target_compile_definitions(sentinel PRIVATE SENTINEL_HAS_SERVER=1)
endif()

# ---- tests ----
if(SENTINEL_BUILD_TESTS)
  enable_testing()
  add_executable(sentinel_tests
    tests/test_portrange.cpp tests/test_logscan.cpp tests/test_password.cpp tests/test_scanner.cpp
    tests/test_net.cpp tests/test_rules.cpp tests/test_result.cpp tests/test_report.cpp)
  target_link_libraries(sentinel_tests PRIVATE sentinel_core GTest::gtest_main sentinel_warnings)
  target_compile_definitions(sentinel_tests PRIVATE SENTINEL_SOURCE_DIR="${CMAKE_SOURCE_DIR}" ${_win_defs})
  if(SENTINEL_BUILD_SERVER)
    target_sources(sentinel_tests PRIVATE tests/test_server.cpp)
    target_link_libraries(sentinel_tests PRIVATE sentinel_server)
    target_include_directories(sentinel_tests SYSTEM PRIVATE ${httplib_SOURCE_DIR})
  endif()
  include(GoogleTest)
  gtest_discover_tests(sentinel_tests DISCOVERY_MODE PRE_TEST)
endif()

# ---- install ----
if(SENTINEL_INSTALL)
  include(CMakePackageConfigHelpers)
  set(_targets sentinel_core sentinel)
  if(SENTINEL_BUILD_SERVER)
    list(APPEND _targets sentinel_server)
  endif()
  install(TARGETS ${_targets} EXPORT SentinelTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
  install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
  install(FILES ${GEN_DIR}/sentinel/version.hpp DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sentinel)
  install(FILES rules/default_rules.json DESTINATION ${CMAKE_INSTALL_DATADIR}/sentinel/rules)
  install(DIRECTORY samples/ DESTINATION ${CMAKE_INSTALL_DATADIR}/sentinel/samples)
  install(FILES LICENSE README.md CHANGELOG.md DESTINATION ${CMAKE_INSTALL_DOCDIR})

  set(_cfgdir ${CMAKE_INSTALL_LIBDIR}/cmake/Sentinel)
  install(EXPORT SentinelTargets NAMESPACE sentinel:: DESTINATION ${_cfgdir})
  configure_package_config_file(cmake/SentinelConfig.cmake.in ${CMAKE_BINARY_DIR}/SentinelConfig.cmake
    INSTALL_DESTINATION ${_cfgdir})
  write_basic_package_version_file(${CMAKE_BINARY_DIR}/SentinelConfigVersion.cmake
    VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
  install(FILES ${CMAKE_BINARY_DIR}/SentinelConfig.cmake ${CMAKE_BINARY_DIR}/SentinelConfigVersion.cmake
    DESTINATION ${_cfgdir})
endif()
