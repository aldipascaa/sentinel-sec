# sentinel_embed(<output.cpp> <symbol> <file>|<mime> ...)
# Generates a C++ source defining `sentinel::EmbeddedAsset <symbol>[]` and `<symbol>Count`
# (see include/sentinel/embedded.hpp) holding the given files. The file name (without
# directories) becomes EmbeddedAsset::name. Files are NUL-terminated in memory (size excludes it).
function(sentinel_embed output symbol)
  set(body "")
  set(table "")
  set(i 0)
  foreach(spec IN LISTS ARGN)
    string(REPLACE "|" ";" parts "${spec}")
    list(GET parts 0 path)
    list(GET parts 1 mime)
    get_filename_component(fname "${path}" NAME)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${path}")
    file(READ "${path}" hex HEX)
    string(REGEX REPLACE "([0-9a-f][0-9a-f])" [[0x\1,]] bytes "${hex}")
    string(APPEND body "const unsigned char a${i}[] = {${bytes}0x00};\n")
    string(APPEND table "  {\"${fname}\", \"${mime}\", a${i}, sizeof(a${i}) - 1},\n")
    math(EXPR i "${i} + 1")
  endforeach()
  file(WRITE "${output}.tmp"
    "#include \"sentinel/embedded.hpp\"\n\nnamespace {\n${body}}  // namespace\n\n"
    "namespace sentinel {\n"
    "extern const EmbeddedAsset ${symbol}[];\nextern const std::size_t ${symbol}Count;\n"
    "const EmbeddedAsset ${symbol}[] = {\n${table}};\n"
    "const std::size_t ${symbol}Count = ${i};\n}  // namespace sentinel\n")
  execute_process(COMMAND ${CMAKE_COMMAND} -E copy_if_different "${output}.tmp" "${output}")
endfunction()
