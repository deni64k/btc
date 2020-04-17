cmake_minimum_required (VERSION 3.16)
project (btc LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

if (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
  string(REGEX REPLACE "[ ^]/W[0-9][ $]" " " CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})
  add_compile_options(/std:c++latest /experimental:preprocessor /W4) # /WX
  add_compile_options($<$<CONFIG:Release>:/O2>)
  add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN
                          _CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_WARNINGS)
else ()
  add_compile_options(-Wall -Werror -pedantic $<$<CXX_COMPILER_ID:GNU>:-fconcepts>)
  add_compile_options($<$<CONFIG:Debug>:-g -ggdb>)
  add_compile_options($<$<CONFIG:Release>:-O3 -march=native>)
endif ()

include(CheckLanguage)
check_language(CUDA)
if (CMAKE_CUDA_COMPILER)
  enable_language(CUDA)
  add_compile_definitions(HAVE_CUDA)
else ()
  message(STATUS "No CUDA support")
endif ()

find_package(Boost REQUIRED)
set(OPENSSL_USE_STATIC_LIBS ON)
find_package(OpenSSL REQUIRED)
find_package(OpenCL REQUIRED)

include_directories(
        $<$<NOT:$<PLATFORM_ID:Windows>>:"/usr/local/include">
        "${btc_SOURCE_DIR}/src"
        "${btc_SOURCE_DIR}/vendor")

add_subdirectory (src)
