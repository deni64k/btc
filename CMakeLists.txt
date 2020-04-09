cmake_minimum_required (VERSION 2.8.11)
project (btc)

if (WIN32)
    set(CMAKE_CXX_FLAGS
        "${CMAKE_CXX_FLAGS} /std:c++latest /W4 /experimental:preprocessor") # /WX
    set(CMAKE_CXX_FLAGS_RELEASE
        "${CMAKE_CXX_FLAGS_RELEASE} /O2")
    add_definitions(/DNOMINMAX /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS /D_CRT_NONSTDC_NO_WARNINGS)
else ()
    set(CMAKE_CXX_FLAGS
        "${CMAKE_CXX_FLAGS} -Wall -Werror -pedantic")
    set(CMAKE_CXX_FLAGS_DEBUG
        "${CMAKE_CXX_FLAGS_DEBUG} -ggdb")
    set(CMAKE_CXX_FLAGS_RELEASE
        "${CMAKE_CXX_FLAGS_RELEASE} -O3 -march=native")
endif ()

set(OPENSSL_USE_STATIC_LIBS ON)
find_package(OpenSSL REQUIRED)
find_package(OpenCL REQUIRED)

#find_path(BoostPreprocessor_INCLUDE_DIR NAMES preprocessor.hpp PATH_SUFFIXES boost)
#include_directories(${BoostPreprocessor_INCLUDE_DIR})
include_directories("${btc_SOURCE_DIR}/vcpkg/installed/x64-windows/include")

include_directories(
        "/usr/local/include"
        "${OPENSSL_INCLUDE_DIR}"
        "${OpenCL_INCLUDE_DIRS}"
        "${btc_SOURCE_DIR}/src"
        "${btc_SOURCE_DIR}/vendor")

add_subdirectory (src)
