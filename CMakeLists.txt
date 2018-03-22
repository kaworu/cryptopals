include(CheckLibraryExists)

cmake_minimum_required(VERSION 2.6.0)
project(cryptopals)

add_definitions(-std=c11 -Wall -Werror)
set(CMAKE_C_FLAGS_DEBUG   "${CMAKE_C_FLAGS} -O0 -g")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -O3 -march=native")

set(SRCS
    ${PROJECT_SOURCE_DIR}/src/bytes.c
    ${PROJECT_SOURCE_DIR}/src/xor.c
    ${PROJECT_SOURCE_DIR}/src/break_plaintext.c
    ${PROJECT_SOURCE_DIR}/src/break_single_byte_xor.c
    ${PROJECT_SOURCE_DIR}/src/break_repeating_key_xor.c
)

# compat stuff.
check_library_exists(c explicit_bzero "strings.h" HAVE_EXPLICIT_BZERO)
if(NOT HAVE_EXPLICIT_BZERO)
    set(SRCS ${SRCS} "${PROJECT_SOURCE_DIR}/src/compat/explicit_bzero.c")
endif()
check_library_exists(c freezero "stdlib.h" HAVE_FREEZERO)
if(NOT HAVE_FREEZERO)
    set(SRCS ${SRCS} "${PROJECT_SOURCE_DIR}/src/compat/freezero.c")
endif()

# µnit Testing Framework
include_directories("${PROJECT_SOURCE_DIR}/munit")
add_library(munit ${PROJECT_SOURCE_DIR}/munit/munit.c)

# Our library stuff.
include_directories("${PROJECT_SOURCE_DIR}/src")
add_library(cryptopals ${SRCS})

# Test executable.
add_executable(testrunner
    ${PROJECT_SOURCE_DIR}/tests/test_bytes.c
    ${PROJECT_SOURCE_DIR}/tests/test_xor.c
    ${PROJECT_SOURCE_DIR}/tests/test_break_plaintext.c
    ${PROJECT_SOURCE_DIR}/tests/test_break_single_byte_xor.c
    ${PROJECT_SOURCE_DIR}/tests/test_break_repeating_key_xor.c
    ${PROJECT_SOURCE_DIR}/tests/main.c)
target_link_libraries(testrunner munit cryptopals)
