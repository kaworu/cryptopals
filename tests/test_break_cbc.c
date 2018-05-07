/*
 * test_break_cbc.c
 */
#include "munit.h"
#include "helpers.h"
#include "break_cbc.h"


/* Test that admin=true cannot be injected */
static MunitResult
test_cbc_bitflipping_0(const MunitParameter *params, void *data)
{
	struct bytes *key = bytes_randomized(16);
	struct bytes *iv  = bytes_randomized(16);
	if (key == NULL || iv == NULL)
		munit_error("bytes_randomized");
	struct bytes *payload = bytes_from_str("X;admin=true");
	if (payload == NULL)
		munit_error("bytes_from_str");

	struct bytes *ciphertext = cbc_bitflipping_oracle(payload, key, iv);
	munit_assert_not_null(ciphertext);

	const int ret = cbc_bitflipping_verifier(ciphertext, key, iv);
	munit_assert_int(ret, ==, 0);

	bytes_free(ciphertext);
	bytes_free(payload);
	bytes_free(iv);
	bytes_free(key);
	return (MUNIT_OK);
}


/* Set 2 / Challenge 16 */
static MunitResult
test_cbc_bitflipping_1(const MunitParameter *params, void *data)
{
	struct bytes *key = bytes_randomized(16);
	struct bytes *iv  = bytes_randomized(16);
	if (key == NULL || iv == NULL)
		munit_error("bytes_randomized");

	struct bytes *ciphertext = cbc_bitflipping_breaker(key, iv);
	munit_assert_not_null(ciphertext);

	const int ret = cbc_bitflipping_verifier(ciphertext, key, iv);
	munit_assert_int(ret, ==, 1);

	bytes_free(ciphertext);
	bytes_free(iv);
	bytes_free(key);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_break_cbc_suite_tests[] = {
	{ "cbc_bitflipping-0", test_cbc_bitflipping_0, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "cbc_bitflipping-1", test_cbc_bitflipping_1, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
