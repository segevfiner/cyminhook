cmake_minimum_required(VERSION 3.22)
project(cyminhook)
find_package(PythonExtensions REQUIRED)
find_package(Cython REQUIRED)

add_subdirectory(minhook)
add_subdirectory(cyminhook)
