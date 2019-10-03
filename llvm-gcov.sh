#!/bin/sh
#
# Copied from http://logan.tw/posts/2015/04/28/check-code-coverage-with-clang-and-lcov/

exec llvm-cov-6.0 gcov "$@"
