# tools/reg_codegen/CMakeLists.txt

# Source files.
file(GLOB_RECURSE REG_CODEGEN_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
)

# https://github.com/nlohmann/json.
find_package(nlohmann_json CONFIG REQUIRED)
find_package(cxxopts CONFIG REQUIRED)

add_executable(xino_reg_codegen ${REG_CODEGEN_SOURCES})

target_compile_options(xino_reg_codegen PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wno-unused-parameter
)

target_link_libraries(xino_reg_codegen PRIVATE
  nlohmann_json::nlohmann_json
  cxxopts::cxxopts
)

install(TARGETS xino_reg_codegen RUNTIME DESTINATION bin)
