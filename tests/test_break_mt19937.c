/*
 * test_break_mt19937.c
 */
#include <time.h>

#include "munit.h"
#include "break_mt19937.h"


/* Set 3 / Challenge 22 */
static MunitResult
test_break_mt19937(const MunitParameter *params, void *data)
{
	const uint32_t before = time(NULL);
	uint32_t after = before;
	uint32_t seed = 0;

	const uint32_t rnd = mt19937_time_seed_oracle(&after, &seed);
	munit_assert_uint32(seed, >, before);
	munit_assert_uint32(seed, <, after);

	const uint32_t guess = mt19937_time_seed_breaker(before, after, rnd);
	munit_assert_uint32(guess, ==, seed);

	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_break_mt19937_suite_tests[] = {
	{ "break_mt19937", test_break_mt19937, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
