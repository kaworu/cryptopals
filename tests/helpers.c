/*
 * helpers.c
 *
 * Some testing help stuff.
 */
#include <limits.h>
#include <stdlib.h>

#include "helpers.h"


static unsigned int seed = 0;


void
init_seed(void)
{
	static int initialized = 0;

	if (!initialized) {
		seed = munit_rand_uint32();
		initialized = 1;
	}
}


void *
srand_reset(const MunitParameter *params, void *user_data)
{
	init_seed();
	srand(seed);
	return (NULL);
}


uint64_t
rand_uint64(void)
{
	uint64_t lo = munit_rand_uint32();
	uint64_t hi = munit_rand_uint32();
	return ((hi << 32) | lo);
}
