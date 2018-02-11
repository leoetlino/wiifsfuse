find_path(FUSE_INCLUDE_DIR fuse.h)
find_library(FUSE_LIBRARY fuse)

set(CMAKE_REQUIRED_INCLUDES ${FUSE_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(FUSE DEFAULT_MSG FUSE_INCLUDE_DIR FUSE_LIBRARY)

mark_as_advanced(FUSE_INCLUDE_DIR FUSE_LIBRARY)

add_library(Fuse::Fuse UNKNOWN IMPORTED)
set_target_properties(Fuse::Fuse PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES ${FUSE_INCLUDE_DIR}
  IMPORTED_LOCATION ${FUSE_LIBRARY}
)
