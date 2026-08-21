cmake_minimum_required(VERSION 3.22...4.4)

project(${SKBUILD_PROJECT_NAME} LANGUAGES C)

find_package(
  Python
  COMPONENTS Interpreter Development.Module
  REQUIRED)
find_package(Cython MODULE REQUIRED VERSION 3.0)
include(UseCython)

add_subdirectory(minhook)

cython_transpile(cyminhook/_cyminhook.pyx LANGUAGE C
                 OUTPUT_VARIABLE _cyminhook_c)

python_add_library(_cyminhook MODULE ${_cyminhook_c} WITH_SOABI)
target_link_libraries(_cyminhook PRIVATE minhook)
install(TARGETS _cyminhook LIBRARY DESTINATION cyminhook)
