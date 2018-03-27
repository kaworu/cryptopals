include(CheckLibraryExists)

cmake_minimum_required(VERSION 2.6.0)
project(cryptopals)

add_compile_options(-std=c11 -Wall -Wextra -Werror)
add_compile_options(-fstack-protector-strong -o aslr -fpie)
set(CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS} -pie)
# Per build type flags.
set(CMAKE_C_FLAGS_DEBUG    "${CMAKE_C_FLAGS} -O0 -g -fsanitize=undefined")
set(CMAKE_C_FLAGS_COVERAGE "${CMAKE_C_FLAGS} -O0 -g -fprofile-arcs -ftest-coverage")
if(CMAKE_BUILD_TYPE MATCHES COVERAGE)
    set(CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS} --coverage)
endif()

# OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIRS})
link_directories(${OPENSSL_LIBRARIES})

# Our cryptopals library.
set(SRCS
    ${PROJECT_SOURCE_DIR}/src/bytes.c
    ${PROJECT_SOURCE_DIR}/src/xor.c
    ${PROJECT_SOURCE_DIR}/src/aes.c
    ${PROJECT_SOURCE_DIR}/src/break_plaintext.c
    ${PROJECT_SOURCE_DIR}/src/break_single_byte_xor.c
    ${PROJECT_SOURCE_DIR}/src/break_repeating_key_xor.c
)
include_directories("${PROJECT_SOURCE_DIR}/src")
# compat stuff.
check_library_exists(c explicit_bzero "strings.h" HAVE_EXPLICIT_BZERO)
if(NOT HAVE_EXPLICIT_BZERO)
    set(SRCS ${SRCS} "${PROJECT_SOURCE_DIR}/src/compat/explicit_bzero.c")
endif()
check_library_exists(c freezero "stdlib.h" HAVE_FREEZERO)
if(NOT HAVE_FREEZERO)
    set(SRCS ${SRCS} "${PROJECT_SOURCE_DIR}/src/compat/freezero.c")
endif()
add_library(cryptopals ${SRCS})
target_link_libraries(cryptopals ${OPENSSL_LIBRARIES})

# µnit Testing Framework
set(MUNIT_SRCS
    ${PROJECT_SOURCE_DIR}/munit/munit.c
)
include_directories("${PROJECT_SOURCE_DIR}/munit")
# XXX: clang choke on munit.c with -Wmissing-field-initializers
set_source_files_properties(${MUNIT_SRCS} PROPERTIES COMPILE_FLAGS -Wno-missing-field-initializers)
add_library(munit ${PROJECT_SOURCE_DIR}/munit/munit.c)

# Test stuff.
set(TEST_SRCS
    ${PROJECT_SOURCE_DIR}/tests/test_bytes.c
    ${PROJECT_SOURCE_DIR}/tests/test_xor.c
    ${PROJECT_SOURCE_DIR}/tests/test_break_plaintext.c
    ${PROJECT_SOURCE_DIR}/tests/test_break_single_byte_xor.c
    ${PROJECT_SOURCE_DIR}/tests/test_break_repeating_key_xor.c
    ${PROJECT_SOURCE_DIR}/tests/test_aes.c
    ${PROJECT_SOURCE_DIR}/tests/main.c
)
# XXX: we don't use much µnit parameters.
set_source_files_properties(${TEST_SRCS} PROPERTIES COMPILE_FLAGS -Wno-unused-parameter)
add_executable(testrunner ${TEST_SRCS})
target_link_libraries(testrunner munit cryptopals)
