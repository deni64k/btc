add_executable(btc
        main.cxx
        scrypt.cxx
        scrypt-sse2.cxx)

target_link_libraries(btc ${OPENSSL_LIBRARIES})
target_link_libraries(btc ${OpenCL_LIBRARIES})

set_target_properties(btc PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    COMPILE_OPTIONS "-fconcepts")

add_custom_target(copy_shaders_directory ALL
    COMMAND ${CMAKE_COMMAND} -E copy_directory 
        "${CMAKE_SOURCE_DIR}/src/shaders" "${CMAKE_BINARY_DIR}/shaders"
    COMMENT "Copy shaders directory to build tree"
    VERBATIM)
