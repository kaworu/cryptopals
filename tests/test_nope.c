/*
 * test_nope.c
 */
#include "munit.h"
#include "helpers.h"
#include "nope.h"


static MunitResult
test_nope_keylength(const MunitParameter *params, void *data)
{
	const size_t len = nope_keylength();

	munit_assert_size(len, ==, 1);
	munit_assert_int(nope_keylength == nope.keylength, ==, 1);

	return (MUNIT_OK);
}


static MunitResult
test_nope_expkeylength(const MunitParameter *params, void *data)
{
	const size_t len = nope_expkeylength();

	munit_assert_size(len, ==, 2);
	munit_assert_int(nope_expkeylength == nope.expkeylength, ==, 1);

	return (MUNIT_OK);
}


static MunitResult
test_nope_blocksize(const MunitParameter *params, void *data)
{
	const size_t len = nope_blocksize();

	munit_assert_size(len, ==, 16);
	munit_assert_int(nope_blocksize == nope.blocksize, ==, 1);

	return (MUNIT_OK);
}


/* Error conditions */
static MunitResult
test_nope_expand_key_0(const MunitParameter *params, void *data)
{
	struct bytes *short_key = bytes_randomized(nope_keylength() - 1);
	struct bytes *long_key  = bytes_randomized(nope_keylength() + 1);
	struct bytes *empty     = bytes_randomized(0);
	if (short_key == NULL || long_key == NULL || empty == NULL)
		munit_error("bytes_randomized");

	/* when NULL is given */
	munit_assert_null(nope_expand_key(NULL));
	/* when the key length is wrong */
	munit_assert_null(nope_expand_key(empty));
	munit_assert_null(nope_expand_key(short_key));
	munit_assert_null(nope_expand_key(long_key));

	munit_assert_int(nope_expand_key == nope.expand_key, ==, 1);

	bytes_free(empty);
	bytes_free(long_key);
	bytes_free(short_key);
	return (MUNIT_OK);
}


static MunitResult
test_nope_expand_key_1(const MunitParameter *params, void *data)
{
	struct bytes *key = bytes_randomized(nope_keylength());
	if (key == NULL)
		munit_error("bytes_randomized");

	struct bytes *expkey = nope_expand_key(key);
	munit_assert_not_null(expkey);
	munit_assert_size(expkey->len, ==, nope_expkeylength());

	bytes_free(expkey);
	bytes_free(key);
	return (MUNIT_OK);
}


/* Error conditions */
static MunitResult
test_nope_crypt_0(const MunitParameter *params, void *data)
{
	struct bytes *short_input  = bytes_randomized(nope_blocksize() - 1);
	struct bytes *long_input   = bytes_randomized(nope_blocksize() + 1);
	struct bytes *input        = bytes_randomized(nope_blocksize());
	struct bytes *short_expkey = bytes_randomized(nope_expkeylength() - 1);
	struct bytes *long_expkey  = bytes_randomized(nope_expkeylength() + 1);
	struct bytes *expkey       = bytes_randomized(nope_expkeylength());
	struct bytes *empty        = bytes_randomized(0);
	if (short_input == NULL || long_input == NULL || input == NULL ||
		    short_expkey == NULL || long_expkey == NULL ||
		    expkey == NULL || empty == NULL) {
		munit_error("bytes_randomized");
	}

	/* when NULL is given */
	munit_assert_null(nope_crypt(NULL,  NULL));
	munit_assert_null(nope_crypt(input, NULL));
	munit_assert_null(nope_crypt(NULL,  expkey));

	/* when the expanded key length is wrong */
	munit_assert_null(nope_crypt(input, empty));
	munit_assert_null(nope_crypt(input, short_expkey));
	munit_assert_null(nope_crypt(input, long_expkey));

	/* when the input length is wrong */
	munit_assert_null(nope_crypt(empty, expkey));
	munit_assert_null(nope_crypt(short_input, expkey));
	munit_assert_null(nope_crypt(long_input, expkey));

	munit_assert_int(nope_crypt == nope.encrypt, ==, 1);
	munit_assert_int(nope_crypt == nope.decrypt, ==, 1);

	bytes_free(empty);
	bytes_free(expkey);
	bytes_free(long_expkey);
	bytes_free(short_expkey);
	bytes_free(input);
	bytes_free(long_input);
	bytes_free(short_input);
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
	struct bytes *expkey = nope_expand_key(key);
	if (expkey == NULL)
		munit_error("nope_expand_key");

	struct bytes *ciphertext = nope_crypt(plaintext, expkey);
	munit_assert_not_null(ciphertext);
	munit_assert_size(ciphertext->len, ==, plaintext->len);
	munit_assert_memory_equal(plaintext->len, ciphertext->data, plaintext->data);

	bytes_free(ciphertext);
	bytes_free(expkey);
	bytes_free(key);
	bytes_free(plaintext);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_nope_suite_tests[] = {
	{ "nope_keylength",    test_nope_keylength,    NULL,        NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nope_expkeylength", test_nope_expkeylength, NULL,        NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nope_blocksize",    test_nope_blocksize,    NULL,        NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nope_expand_key-0", test_nope_expand_key_0, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nope_expand_key-1", test_nope_expand_key_1, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nope_crypt-0",      test_nope_crypt_0,      srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nope_crypt-1",      test_nope_crypt_1,      srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
