include(CheckLibraryExists)

cmake_minimum_required(VERSION 2.6.0)
project(cryptopals)

add_definitions(-std=c11 -Wall)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -g -O0 -Wpacked")

set(SRCS
    ${PROJECT_SOURCE_DIR}/src/bytes.c
    ${PROJECT_SOURCE_DIR}/src/xor.c
    ${PROJECT_SOURCE_DIR}/src/analysis.c
)

# compat stuff.
check_library_exists(c explicit_bzero "strings.h" HAVE_EXPLICIT_BZERO)
if(NOT HAVE_EXPLICIT_BZERO)
    set(SRCS ${SRCS} "${PROJECT_SOURCE_DIR}/src/compat/explicit_bzero.c")
endif()

# µnit Testing Framework
include_directories("${PROJECT_SOURCE_DIR}/munit")
add_library(munit ${PROJECT_SOURCE_DIR}/munit/munit.c)

# Our library stuff.
include_directories("${PROJECT_SOURCE_DIR}/src")
add_library(cryptopals ${SRCS})

# Test executable.
add_executable(testrun
    ${PROJECT_SOURCE_DIR}/tests/test_bytes.c
    ${PROJECT_SOURCE_DIR}/tests/test_xor.c
    ${PROJECT_SOURCE_DIR}/tests/test_analysis.c
    ${PROJECT_SOURCE_DIR}/tests/main.c)
target_link_libraries(testrun munit cryptopals)
