# Just a wrapper around CMake to build, run and clean.

all: build/testrun

test: build/testrun
	./build/testrun

build/testrun: build
	cd build && cmake -DCMAKE_BUILD_TYPE=DEBUG -DCMAKE_VERBOSE_MAKEFILE=YES .. && make

build:
	test -d build || mkdir build

clean:
	rm -rf build

.PHONY: all test clean
