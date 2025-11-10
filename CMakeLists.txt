# tools/CMakeLists.txt
cmake_minimum_required(VERSION 3.20)

project(xino_tools
  VERSION 0.1.0
  DESCRIPTION "xino uKernel host tools"
  LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_subdirectory(reg_codegen)

# cmake --build ... --target style.
find_program(CLANG_FORMAT_EXE NAMES clang-format)
if (CLANG_FORMAT_EXE)
  add_custom_target(style
    COMMAND find reg_codegen
      # Format (*.h, *.c, *.cpp, and *.hpp files).
      -regextype posix-extended -type f -regex ".*\.(c|h|cpp|hpp)$"
      -exec "${CLANG_FORMAT_EXE}" -i {} +
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    VERBATIM
  )
endif()
