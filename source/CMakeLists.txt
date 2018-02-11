add_executable(wiifsfuse
  common/common_types.h
  main.cpp
)

set_target_properties(wiifsfuse PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED ON
  CXX_EXTENSIONS OFF
)

target_include_directories(wiifsfuse
  PRIVATE .
)

add_subdirectory(../../wiifs ../build)
find_package(FMT REQUIRED)
find_package(Fuse REQUIRED)
target_link_libraries(wiifsfuse
  PRIVATE
    fmt::fmt
    Fuse::Fuse
    wiifs
)

target_compile_options(wiifsfuse PRIVATE "-Wall")
target_compile_definitions(wiifsfuse PRIVATE "-D_FILE_OFFSET_BITS=64")
