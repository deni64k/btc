add_executable(btc main.cxx)

target_link_libraries(btc ${OPENSSL_LIBRARIES})

set_target_properties(btc PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    COMPILE_OPTIONS "-fconcepts")
