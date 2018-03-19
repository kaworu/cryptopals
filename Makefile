# Just a wrapper around CMake to build, run and clean.

all: testrun

test: testrun
	./build/testrun

testrun: build
	cd build && cmake -DCMAKE_BUILD_TYPE=DEBUG -DCMAKE_VERBOSE_MAKEFILE=YES .. && make

build:
	test -d build || mkdir build

clean:
	rm -rf build

.PHONY: all test testrun clean
