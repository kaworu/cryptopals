/*
 * test_ecb.c
 */
#include "munit.h"
#include "helpers.h"
#include "nope.h"
#include "ecb.h"


/* Error conditions */
static MunitResult
test_nope_ecb_encrypt_0(const MunitParameter *params, void *data)
{
	struct bytes *key = bytes_randomized(nope_keylength());
	if (key == NULL)
		munit_error("bytes_randomized");

	/* when NULL is given */
	munit_assert_null(nope_ecb_encrypt(NULL, NULL));
	munit_assert_null(nope_ecb_encrypt(NULL, key));

	bytes_free(key);
	return (MUNIT_OK);
}


static MunitResult
test_nope_ecb_encrypt_1(const MunitParameter *params, void *data)
{
	const size_t blocksize = nope_blocksize();

	for (size_t i = 0; i <= 3 * blocksize; i++) {
		struct bytes *key = bytes_randomized(nope_keylength());
		struct bytes *plaintext = bytes_randomized(i);
		if (key == NULL || plaintext == NULL)
			munit_error("bytes_randomized");
		struct bytes *expected = bytes_pkcs7_padded(plaintext, blocksize);
		if (expected == NULL || expected->len % blocksize != 0)
			munit_error("bytes_pkcs7_padded");

		struct bytes *ciphertext = nope_ecb_encrypt(plaintext, NULL);
		munit_assert_not_null(ciphertext);
		munit_assert_size(ciphertext->len, ==, expected->len);
		munit_assert_memory_equal(ciphertext->len, ciphertext->data, expected->data);
		bytes_free(ciphertext);

		ciphertext = nope_ecb_encrypt(plaintext, key);
		munit_assert_not_null(ciphertext);
		munit_assert_size(ciphertext->len, ==, expected->len);
		munit_assert_memory_equal(ciphertext->len, ciphertext->data, expected->data);
		bytes_free(ciphertext);

		bytes_free(expected);
		bytes_free(plaintext);
		bytes_free(key);
	}

	return (MUNIT_OK);
}


/* Error conditions */
static MunitResult
test_nope_ecb_decrypt_0(const MunitParameter *params, void *data)
{
	struct bytes *too_short = bytes_randomized(nope_blocksize() - 1);
	struct bytes *too_long  = bytes_randomized(nope_blocksize() + 1);
	struct bytes *key = bytes_randomized(nope_keylength());
	if (too_short == NULL || too_long == NULL || key == NULL)
		munit_error("bytes_randomized");

	/* when NULL is given */
	munit_assert_null(nope_ecb_decrypt(NULL, NULL));
	munit_assert_null(nope_ecb_decrypt(NULL, key));

	/* when the input length is incorrect */
	munit_assert_null(nope_ecb_decrypt(too_short, NULL));
	munit_assert_null(nope_ecb_decrypt(too_short, key));
	munit_assert_null(nope_ecb_decrypt(too_long, NULL));
	munit_assert_null(nope_ecb_decrypt(too_long,  key));

	bytes_free(key);
	bytes_free(too_long);
	bytes_free(too_short);
	return (MUNIT_OK);
}


static MunitResult
test_nope_ecb_decrypt_1(const MunitParameter *params, void *data)
{
	const size_t blocksize = nope_blocksize();

	for (size_t i = 0; i <= 3 * blocksize; i++) {
		struct bytes *key = bytes_randomized(nope_keylength());
		struct bytes *expected = bytes_randomized(i);
		if (key == NULL || expected == NULL)
			munit_error("bytes_randomized");
		struct bytes *ciphertext = bytes_pkcs7_padded(expected, blocksize);
		if (ciphertext == NULL || ciphertext->len % blocksize != 0)
			munit_error("bytes_pkcs7_padded");

		struct bytes *plaintext = nope_ecb_decrypt(ciphertext, NULL);
		munit_assert_not_null(plaintext);
		munit_assert_size(plaintext->len, ==, expected->len);
		munit_assert_memory_equal(plaintext->len, plaintext->data, expected->data);
		bytes_free(plaintext);

		plaintext = nope_ecb_decrypt(ciphertext, key);
		munit_assert_not_null(plaintext);
		munit_assert_size(plaintext->len, ==, expected->len);
		munit_assert_memory_equal(plaintext->len, plaintext->data, expected->data);
		bytes_free(plaintext);

		bytes_free(ciphertext);
		bytes_free(expected);
		bytes_free(key);
	}

	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_ecb_suite_tests[] = {
	{ "nope_ecb_encrypt-0", test_nope_ecb_encrypt_0, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nope_ecb_encrypt-1", test_nope_ecb_encrypt_1, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nope_ecb_decrypt-0", test_nope_ecb_decrypt_0, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nope_ecb_decrypt-1", test_nope_ecb_decrypt_1, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
