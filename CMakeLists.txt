cmake_minimum_required(VERSION 3.22...4.4)

project(${SKBUILD_PROJECT_NAME})

find_package(
  Python
  COMPONENTS Interpreter Development.Module
  REQUIRED)
find_package(Cython MODULE REQUIRED VERSION 3.0)
include(UseCython)

add_subdirectory(minhook)
add_subdirectory(cyminhook)
