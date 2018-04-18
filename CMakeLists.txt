include(CheckLibraryExists)

cmake_minimum_required(VERSION 2.6.0)
project(cryptopals)

add_compile_options(-std=c11 -Wall -Wextra -Werror -fno-strict-aliasing)
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
    ${PROJECT_SOURCE_DIR}/src/break_plaintext.c
    ${PROJECT_SOURCE_DIR}/src/break_single_byte_xor.c
    ${PROJECT_SOURCE_DIR}/src/break_repeating_key_xor.c
    ${PROJECT_SOURCE_DIR}/src/aes.c
    ${PROJECT_SOURCE_DIR}/src/break_aes.c
)
include_directories("${PROJECT_SOURCE_DIR}/src")
# compat stuff.
macro(use_compat_unless_exists LIBRARY FUNCTION LOCATION VARIABLE)
    check_library_exists(LIBRARY FUNCTION LOCATION VARIABLE)
    if (NOT ${VARIABLE})
        set(SRCS ${SRCS} "${PROJECT_SOURCE_DIR}/src/compat/${FUNCTION}.c")
    endif()
endmacro()
use_compat_unless_exists(c explicit_memset "string.h"  HAVE_EXPLICIT_MEMSET)
use_compat_unless_exists(c explicit_bzero  "strings.h" HAVE_EXPLICIT_BZERO)
use_compat_unless_exists(c freezero        "stdlib.h"  HAVE_FREEZERO)
use_compat_unless_exists(c timingsafe_bcmp "string.h"  HAVE_TIMINGSAFE_BCMP)
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
    ${PROJECT_SOURCE_DIR}/tests/test_break_aes.c
    ${PROJECT_SOURCE_DIR}/tests/main.c
)
# XXX: we don't use much µnit parameters.
set_source_files_properties(${TEST_SRCS} PROPERTIES COMPILE_FLAGS -Wno-unused-parameter)
add_executable(testrunner ${TEST_SRCS})
target_link_libraries(testrunner munit cryptopals)
