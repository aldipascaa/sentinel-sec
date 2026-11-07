# Embed a file as a C byte array: <symbol>[] and <symbol>Size.
function(sentinel_embed input output symbol)
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${input})
  file(READ ${input} hex HEX)
  string(REGEX REPLACE "([0-9a-f][0-9a-f])" [[0x\1,]] bytes "${hex}")
  file(WRITE ${output}.tmp
    "#include <cstddef>\nextern const unsigned char ${symbol}[];\nextern const std::size_t ${symbol}Size;\n"
    "const unsigned char ${symbol}[] = {${bytes}0x00};\nconst std::size_t ${symbol}Size = sizeof(${symbol}) - 1;\n")
  execute_process(COMMAND ${CMAKE_COMMAND} -E copy_if_different ${output}.tmp ${output})
endfunction()
