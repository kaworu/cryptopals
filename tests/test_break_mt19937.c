/*
 * test_break_mt19937.c
 */
#include <time.h>

#include "munit.h"
#include "helpers.h"
#include "break_mt19937.h"


/* Set 3 / Challenge 22 */
static MunitResult
test_mt19937_time_seeder_breaker(const MunitParameter *params, void *data)
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


/* Set 3 / Challenge 23 */
static MunitResult
test_mt19937_clone(const MunitParameter *params, void *data)
{
	const uint32_t seed  = munit_rand_uint32();
	struct mt19937_generator *gen = mt19937_init(seed);
	if (gen == NULL)
		munit_error("mt19937_init");

	struct mt19937_generator *clone = mt19937_clone(gen);
	munit_assert_not_null(clone);

	uint32_t original = 0, cloned = 0;
	if (mt19937_next_uint32(gen, &original) != 0)
		munit_error("mt19937_next_uint32");
	if (mt19937_next_uint32(clone, &cloned) != 0)
		munit_error("mt19937_next_uint32");
	munit_assert_uint32(cloned, ==, original);

	mt19937_free(clone);
	mt19937_free(gen);
	return (MUNIT_OK);
}


/* Set 3 / Challenge 24 */
static MunitResult
test_mt19937_encryption_breaker(const MunitParameter *params, void *data)
{
	const uint16_t key = munit_rand_uint32() & 0xffff;
	uint16_t guessed = 0;

	struct bytes *prefix = bytes_randomized(munit_rand_int_range(1, 256));
	if (prefix == NULL)
		munit_error("bytes_randomized");
	struct bytes *known = bytes_repeated(14, 'A');
	if (known == NULL)
		munit_error("bytes_repeated");
	const struct bytes *const parts[] = { prefix, known };
	struct bytes *payload = bytes_joined_const(parts, sizeof(parts) / sizeof(*parts));
	if (payload == NULL)
		munit_error("bytes_joined_const");

	struct bytes *ciphertext = mt19937_encrypt(payload, key);
	if (ciphertext == NULL)
		munit_error("mt19937_encrypt");

	const int ret = mt19937_encryption_breaker(ciphertext, known, &guessed);
	munit_assert_int(ret, ==, 0);
	munit_assert_uint16(guessed, ==, key);

	bytes_free(ciphertext);
	bytes_free(payload);
	bytes_free(known);
	bytes_free(prefix);
	return (MUNIT_OK);
}


/* Set 3 / Challenge 24 */
static MunitResult
test_mt19937_token_breaker(const MunitParameter *params, void *data)
{
	const uint32_t delta = munit_rand_int_range(1, 256);
	const uint32_t now = time(NULL) - delta;
	const size_t tokenlen = 16;
	uint32_t *token   = munit_calloc(tokenlen, sizeof(uint32_t));
	uint32_t *garbage = munit_calloc(tokenlen, sizeof(uint32_t));

	/* create the generator */
	struct mt19937_generator *gen = mt19937_init(now);
	if (gen == NULL)
		munit_error("mt19937_init");
	/* generate the token and the garbage one */
	for (size_t i = 0; i < tokenlen; i++) {
		if (mt19937_next_uint32(gen, token + i) != 0)
			munit_error("mt19937_next_uint32");
		garbage[i] = munit_rand_uint32();
	}

	int ret = mt19937_token_breaker(token, tokenlen);
	munit_assert_int(ret, ==,  0);
	ret = mt19937_token_breaker(garbage, tokenlen);
	munit_assert_int(ret, ==,  1);
	ret = mt19937_token_breaker(NULL, tokenlen);
	munit_assert_int(ret, ==, -1);

	mt19937_free(gen);
	free(garbage);
	free(token);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_break_mt19937_suite_tests[] = {
	{ "time_seeder", test_mt19937_time_seeder_breaker, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "clone",       test_mt19937_clone,               srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "encrypt",     test_mt19937_encryption_breaker,  srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "token",       test_mt19937_token_breaker,       srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
