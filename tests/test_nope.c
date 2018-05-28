/*
 * test_nope.c
 */
#include "munit.h"
#include "helpers.h"
#include "nope.h"


/* Error conditions */
static MunitResult
test_nope_crypt_0(const MunitParameter *params, void *data)
{
	struct bytes *too_short = bytes_randomized(nope_blocksize() - 1);
	struct bytes *too_long  = bytes_randomized(nope_blocksize() + 1);
	struct bytes *key = bytes_randomized(nope_keylength());
	if (too_short == NULL || too_long == NULL || key == NULL)
		munit_error("bytes_randomized");

	/* when NULL is given */
	munit_assert_null(nope_crypt(NULL, NULL));
	munit_assert_null(nope_crypt(NULL, key));

	/* when the input length is incorrect */
	munit_assert_null(nope_crypt(too_short, NULL));
	munit_assert_null(nope_crypt(too_short, key));
	munit_assert_null(nope_crypt(too_long, NULL));
	munit_assert_null(nope_crypt(too_long,  key));

	bytes_free(key);
	bytes_free(too_long);
	bytes_free(too_short);
	return (MUNIT_OK);
}


static MunitResult
test_nope_crypt_1(const MunitParameter *params, void *data)
{
	struct bytes *plaintext = bytes_from_str("YELLOW SUBMARINE");
	if (plaintext == NULL)
		munit_error("bytes_from_str");
	struct bytes *key = bytes_randomized(nope_keylength());
	if (key == NULL)
		munit_error("bytes_randomized");

	/* loop twice, one with the key and one with NULL as key */
	for (size_t i = 0; i < 2; i++) {
		struct bytes *loop_key = i == 0 ? NULL : key;
		struct bytes *ciphertext = nope_crypt(plaintext, loop_key);
		munit_assert_not_null(ciphertext);
		munit_assert_size(ciphertext->len, ==, plaintext->len);
		munit_assert_memory_equal(plaintext->len, ciphertext->data, plaintext->data);

		bytes_free(ciphertext);
	}

	bytes_free(key);
	bytes_free(plaintext);
	return (MUNIT_OK);
}


static MunitResult
test_nope_keylength(const MunitParameter *params, void *data)
{
	const size_t len = nope_keylength();
	munit_assert_size(len, ==, 0);
	return (MUNIT_OK);
}


static MunitResult
test_nope_blocksize(const MunitParameter *params, void *data)
{
	const size_t len = nope_blocksize();
	munit_assert_size(len, ==, 16);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_nope_suite_tests[] = {
	{ "nope_keylength", test_nope_keylength, NULL,        NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nope_blocksize", test_nope_blocksize, NULL,        NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nope_crypt-0",   test_nope_crypt_0,   srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nope_crypt-1",   test_nope_crypt_1,   srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
