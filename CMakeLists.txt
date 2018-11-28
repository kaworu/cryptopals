include(CheckLibraryExists)

cmake_minimum_required(VERSION 2.6.0)
project(cryptopals)

add_compile_options(-std=c11 -Wall -Wextra -Werror -fno-strict-aliasing -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_POSIX_SOURCE)
add_compile_options(-fstack-protector-strong -o aslr -fPIC)
set(CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS} -pie)
# Per build type flags.
set(CMAKE_C_FLAGS_DEBUG    "${CMAKE_C_FLAGS} -O0 -g -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS_ASAN     "${CMAKE_C_FLAGS} -O1 -g -fno-omit-frame-pointer -fno-optimize-sibling-calls -fsanitize=address -fsanitize=undefined")
set(CMAKE_C_FLAGS_VALGRIND "${CMAKE_C_FLAGS_RELEASE} -g -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS_COVERAGE "${CMAKE_C_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
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
    ${PROJECT_SOURCE_DIR}/src/bignum.c
    ${PROJECT_SOURCE_DIR}/src/xor.c
    ${PROJECT_SOURCE_DIR}/src/break_plaintext.c
    ${PROJECT_SOURCE_DIR}/src/break_single_byte_xor.c
    ${PROJECT_SOURCE_DIR}/src/break_repeating_key_xor.c
    ${PROJECT_SOURCE_DIR}/src/nope.c
    ${PROJECT_SOURCE_DIR}/src/aes.c
    ${PROJECT_SOURCE_DIR}/src/ecb.c
    ${PROJECT_SOURCE_DIR}/src/cbc.c
    ${PROJECT_SOURCE_DIR}/src/ctr.c
    ${PROJECT_SOURCE_DIR}/src/mt19937.c
    ${PROJECT_SOURCE_DIR}/src/sha1.c
    ${PROJECT_SOURCE_DIR}/src/sha256.c
    ${PROJECT_SOURCE_DIR}/src/md4.c
    ${PROJECT_SOURCE_DIR}/src/mac.c
    ${PROJECT_SOURCE_DIR}/src/dh.c
    ${PROJECT_SOURCE_DIR}/src/srp.c
    ${PROJECT_SOURCE_DIR}/src/break_ecb.c
    ${PROJECT_SOURCE_DIR}/src/break_cbc.c
    ${PROJECT_SOURCE_DIR}/src/break_ctr.c
    ${PROJECT_SOURCE_DIR}/src/break_mt19937.c
    ${PROJECT_SOURCE_DIR}/src/break_mac.c
    ${PROJECT_SOURCE_DIR}/src/break_dh.c
    ${PROJECT_SOURCE_DIR}/src/cookie.c
)
include_directories("${PROJECT_SOURCE_DIR}/src")
# compat stuff, should be prefix scoped if this was a real library.
set(COMPAT_DIR ${PROJECT_SOURCE_DIR}/src/compat)
check_library_exists(c reallocarray "stdlib.h" HAVE_REALLOCARRAY)
if (NOT HAVE_REALLOCARRAY)
    set(SRCS ${SRCS} "${COMPAT_DIR}/reallocarray.c")
endif()
check_library_exists(c recallocarray "stdlib.h" HAVE_RECALLOCARRAY)
if (NOT HAVE_RECALLOCARRAY)
    set(SRCS ${SRCS} "${COMPAT_DIR}/recallocarray.c")
endif()
set_source_files_properties("${COMPAT_DIR}/recallocarray.c" PROPERTIES COMPILE_FLAGS -Wno-sign-compare)
check_library_exists(c freezero "stdlib.h" HAVE_FREEZERO)
if (NOT HAVE_FREEZERO)
    set(SRCS ${SRCS} "${COMPAT_DIR}/freezero.c")
endif()
check_library_exists(c explicit_memset "string.h" HAVE_EXPLICIT_MEMSET)
if (NOT HAVE_EXPLICIT_MEMSET)
    set(SRCS ${SRCS} "${COMPAT_DIR}/explicit_memset.c")
endif()
check_library_exists(c explicit_bzero "strings.h" HAVE_EXPLICIT_BZERO)
if (NOT HAVE_EXPLICIT_BZERO)
    set(SRCS ${SRCS} "${COMPAT_DIR}/explicit_bzero.c")
endif()
check_library_exists(c timingsafe_bcmp "string.h" HAVE_TIMINGSAFE_BCMP)
if (NOT HAVE_TIMINGSAFE_BCMP)
    set(SRCS ${SRCS} "${COMPAT_DIR}/timingsafe_bcmp.c")
endif()
check_library_exists(c strlcpy "string.h" HAVE_STRLCPY)
if (NOT HAVE_STRLCPY)
    set(SRCS ${SRCS} "${COMPAT_DIR}/strlcpy.c")
endif()
check_library_exists(c strlcat "string.h" HAVE_STRLCAT)
if (NOT HAVE_STRLCAT)
    set(SRCS ${SRCS} "${COMPAT_DIR}/strlcat.c")
endif()
check_library_exists(c asprintf "stdio.h" HAVE_ASPRINTF)
if (NOT HAVE_ASPRINTF)
    set(SRCS ${SRCS} "${COMPAT_DIR}/asprintf.c")
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
    ${PROJECT_SOURCE_DIR}/tests/test_bignum.c
    ${PROJECT_SOURCE_DIR}/tests/test_xor.c
    ${PROJECT_SOURCE_DIR}/tests/test_break_plaintext.c
    ${PROJECT_SOURCE_DIR}/tests/test_break_single_byte_xor.c
    ${PROJECT_SOURCE_DIR}/tests/test_break_repeating_key_xor.c
    ${PROJECT_SOURCE_DIR}/tests/test_nope.c
    ${PROJECT_SOURCE_DIR}/tests/test_aes.c
    ${PROJECT_SOURCE_DIR}/tests/test_ecb.c
    ${PROJECT_SOURCE_DIR}/tests/test_cbc.c
    ${PROJECT_SOURCE_DIR}/tests/test_ctr.c
    ${PROJECT_SOURCE_DIR}/tests/test_mt19937.c
    ${PROJECT_SOURCE_DIR}/tests/test_sha1.c
    ${PROJECT_SOURCE_DIR}/tests/test_sha256.c
    ${PROJECT_SOURCE_DIR}/tests/test_md4.c
    ${PROJECT_SOURCE_DIR}/tests/test_mac.c
    ${PROJECT_SOURCE_DIR}/tests/test_dh.c
    ${PROJECT_SOURCE_DIR}/tests/test_srp.c
    ${PROJECT_SOURCE_DIR}/tests/test_break_ecb.c
    ${PROJECT_SOURCE_DIR}/tests/test_break_cbc.c
    ${PROJECT_SOURCE_DIR}/tests/test_break_ctr.c
    ${PROJECT_SOURCE_DIR}/tests/test_break_mt19937.c
    ${PROJECT_SOURCE_DIR}/tests/test_break_mac.c
    ${PROJECT_SOURCE_DIR}/tests/test_break_dh.c
    ${PROJECT_SOURCE_DIR}/tests/test_cookie.c
    ${PROJECT_SOURCE_DIR}/tests/helpers.c
    ${PROJECT_SOURCE_DIR}/tests/main.c
)
# XXX: we don't use much µnit parameters.
set_source_files_properties(${TEST_SRCS} PROPERTIES COMPILE_FLAGS -Wno-unused-parameter)
add_executable(testrunner ${TEST_SRCS})
target_link_libraries(testrunner munit cryptopals)
