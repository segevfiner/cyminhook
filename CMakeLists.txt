cmake_minimum_required(VERSION 3.22)

list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

project(cyminhook)
find_package(PythonExtensions REQUIRED)
find_package(Cython REQUIRED)

add_subdirectory(minhook)
add_subdirectory(cyminhook)
