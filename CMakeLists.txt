cmake_minimum_required(VERSION 3.8)
project(wiifsfuse CXX)

if(CMAKE_GENERATOR MATCHES "Ninja")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fdiagnostics-color")
endif()

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/CMakeModules")

add_subdirectory(source)
