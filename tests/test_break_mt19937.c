/*
 * test_break_mt19937.c
 */
#include <time.h>

#include "munit.h"
#include "break_mt19937.h"


/* Set 3 / Challenge 22 */
static MunitResult
test_break_time_seeder(const MunitParameter *params, void *data)
{
	const uint32_t before = time(NULL);
	uint32_t after = before;
	uint32_t seed = 0, n = 0, guess = 0;

	struct mt19937_generator *gen = mt19937_init(0);
	if (gen == NULL)
		munit_error("mt19937_init");

	int ret = mt19937_time_seeder(gen, &n, &after, &seed);
	munit_assert_int(ret, ==, 0);
	munit_assert_uint32(seed, >, before);
	munit_assert_uint32(seed, <, after);

	ret = mt19937_time_seeder_breaker(before, after, n, &guess);
	munit_assert_int(ret, ==, 0);
	munit_assert_uint32(guess, ==, seed);

	mt19937_free(gen);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_break_mt19937_suite_tests[] = {
	{ "time_seeder", test_break_time_seeder, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
