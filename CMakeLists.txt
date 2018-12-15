cmake_minimum_required (VERSION 2.8.11)
project (btc)

set(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -Wall -Werror -pedantic")
set(CMAKE_CXX_FLAGS_DEBUG
    "${CMAKE_CXX_FLAGS_DEBUG} -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE
    "${CMAKE_CXX_FLAGS_RELEASE} -O3 -march=native")

set(OPENSSL_USE_STATIC_LIBS ON)
find_package(OpenSSL REQUIRED)
find_package(OpenCL REQUIRED)

include_directories(
        "/usr/local/include"
        "${OPENSSL_INCLUDE_DIR}"
        "${OpenCL_INCLUDE_DIRS}"
        "${btc_SOURCE_DIR}/src"
        "${btc_SOURCE_DIR}/vendor")

add_subdirectory (src)
