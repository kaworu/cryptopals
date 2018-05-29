/*
 * test_ecb.c
 */
#include "munit.h"
#include "helpers.h"
#include "nope.h"
#include "ecb.h"

#include "test_ecb.h"


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


/* Error conditions */
static MunitResult
test_aes_128_ecb_encrypt_0(const MunitParameter *params, void *data)
{
	struct bytes *plaintext = bytes_from_str(s1c7_plaintext);
	struct bytes *key = bytes_from_str(s1c7_key);
	struct bytes *empty = bytes_from_str("");
	if (plaintext == NULL || key == NULL || empty == NULL)
		munit_error("bytes_from_str");

	/* when NULL is given */
	munit_assert_null(aes_128_ecb_encrypt(NULL, key));
	munit_assert_null(aes_128_ecb_encrypt(plaintext, NULL));
	/* when the key has not a valid length */
	munit_assert_null(aes_128_ecb_encrypt(plaintext, empty));

	bytes_free(empty);
	bytes_free(key);
	bytes_free(plaintext);
	return (MUNIT_OK);
}


/* Set 1 / Challenge 7 */
static MunitResult
test_aes_128_ecb_encrypt_1(const MunitParameter *params, void *data)
{
	struct bytes *expected = bytes_from_base64(s1c7_ciphertext_base64);
	if (expected == NULL)
		munit_error("bytes_from_base64");
	struct bytes *key = bytes_from_str(s1c7_key);
	struct bytes *plaintext = bytes_from_str(s1c7_plaintext);
	if (key == NULL || plaintext == NULL)
		munit_error("bytes_from_str");

	struct bytes *ciphertext = aes_128_ecb_encrypt(plaintext, key);
	munit_assert_not_null(ciphertext);
	munit_assert_size(ciphertext->len, ==, expected->len);
	munit_assert_memory_equal(ciphertext->len, ciphertext->data,
		    expected->data);

	bytes_free(ciphertext);
	bytes_free(plaintext);
	bytes_free(key);
	bytes_free(expected);
	return (MUNIT_OK);
}


/* Error conditions */
static MunitResult
test_aes_128_ecb_decrypt_0(const MunitParameter *params, void *data)
{
	struct bytes *ciphertext = bytes_from_base64(s1c7_ciphertext_base64);
	if (ciphertext == NULL)
		munit_error("bytes_from_base64");
	struct bytes *key = bytes_from_str(s1c7_key);
	struct bytes *empty = bytes_from_str("");
	if (key == NULL || empty == NULL)
		munit_error("bytes_from_str");

	/* when NULL is given */
	munit_assert_null(aes_128_ecb_decrypt(NULL, key));
	munit_assert_null(aes_128_ecb_decrypt(ciphertext, NULL));
	/* when the key has not a valid length */
	munit_assert_null(aes_128_ecb_decrypt(ciphertext, empty));

	bytes_free(empty);
	bytes_free(key);
	bytes_free(ciphertext);
	return (MUNIT_OK);
}


/* Set 1 / Challenge 7 */
static MunitResult
test_aes_128_ecb_decrypt_1(const MunitParameter *params, void *data)
{
	struct bytes *ciphertext = bytes_from_base64(s1c7_ciphertext_base64);
	if (ciphertext == NULL)
		munit_error("bytes_from_base64");
	struct bytes *key = bytes_from_str(s1c7_key);
	if (key == NULL)
		munit_error("bytes_from_str");

	struct bytes *plaintext = aes_128_ecb_decrypt(ciphertext, key);
	munit_assert_not_null(plaintext);
	munit_assert_size(plaintext->len, ==, strlen(s1c7_plaintext));
	munit_assert_memory_equal(plaintext->len, plaintext->data, s1c7_plaintext);

	bytes_free(plaintext);
	bytes_free(key);
	bytes_free(ciphertext);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_ecb_suite_tests[] = {
	{ "nope_ecb_encrypt-0", test_nope_ecb_encrypt_0, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nope_ecb_encrypt-1", test_nope_ecb_encrypt_1, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nope_ecb_decrypt-0", test_nope_ecb_decrypt_0, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nope_ecb_decrypt-1", test_nope_ecb_decrypt_1, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_ecb_encrypt-0", test_aes_128_ecb_encrypt_0, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_ecb_encrypt-1", test_aes_128_ecb_encrypt_1, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_ecb_decrypt-0", test_aes_128_ecb_decrypt_0, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_ecb_decrypt-1", test_aes_128_ecb_decrypt_1, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
