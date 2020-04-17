add_executable(btc
        main.cxx
        scrypt.cxx
        scrypt-sse2.cxx)

target_link_libraries(btc Boost::headers)
target_link_libraries(btc OpenSSL::Crypto)
target_link_libraries(btc OpenCL::OpenCL)

add_custom_target(copy_shaders_directory ALL
    COMMAND ${CMAKE_COMMAND} -E copy_directory 
        "${CMAKE_SOURCE_DIR}/src/shaders" "${CMAKE_BINARY_DIR}/shaders"
    COMMENT "Copy shaders directory to build tree"
    VERBATIM)
