# Just a wrapper around CMake to build, run and clean.
BUILD_TYPE?=DEBUG

all: testrunner

test: testrunner
	./build/testrunner --show-stderr --log-visible debug
#	--param hostname localhost               \
#	--param server ./python/server.py        \
#	--param filepath ./README.md             \
#	--param delay 2

testrunner: build
	cd build && cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DCMAKE_VERBOSE_MAKEFILE=YES .. && make

build:
	test -d build || mkdir build

clean:
	rm -rf build

.PHONY: all testrunner test clean
