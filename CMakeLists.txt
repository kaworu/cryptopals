cmake_minimum_required(VERSION 2.6.0)
project(cryptopals)

add_definitions(-std=c11 -Wall)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -g -O0 -Wpacked")

# µnit Testing Framework
include_directories("${PROJECT_SOURCE_DIR}/munit")
add_library(munit ${PROJECT_SOURCE_DIR}/munit/munit.c)

# Our library stuff.
include_directories("${PROJECT_SOURCE_DIR}/src")
add_library(cryptopals
    ${PROJECT_SOURCE_DIR}/src/bytes.c)

# Test executable.
add_executable(testrun
    ${PROJECT_SOURCE_DIR}/tests/test_bytes.c
    ${PROJECT_SOURCE_DIR}/tests/main.c)
target_link_libraries(testrun munit cryptopals)
