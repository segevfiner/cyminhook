cython_transpile(_cyminhook.pyx LANGUAGE C
                 OUTPUT_VARIABLE _cyminhook_c)

python_add_library(_cyminhook MODULE ${_cyminhook_c} WITH_SOABI)
target_link_libraries(_cyminhook PRIVATE minhook)
install(TARGETS _cyminhook LIBRARY DESTINATION cyminhook)
