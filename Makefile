# Just a wrapper around CMake to build, run and clean.
BUILD_TYPE?=DEBUG

all: testrunner

test: testrunner
	./build/testrunner --show-stderr --log-visible debug
#	--param mac_hostname localhost                     \
#	--param mac_server ./python/hmac_padding_oracle.py \
#	--param mac_filepath ./README.md                   \
#	--param mac_delay 2

testrunner: build
	cd build && cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DCMAKE_VERBOSE_MAKEFILE=YES .. && make

build:
	mkdir build

clean:
	rm -rf build

.PHONY: all testrunner test clean
