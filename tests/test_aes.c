/*
 * test_aes.c
 */
#include "munit.h"
#include "aes.h"
#include "test_aes.h"


/* Error conditions */
static MunitResult
test_aes_128_ecb_encrypt_0(const MunitParameter *params, void *data)
{
	struct bytes *ciphertext = bytes_from_base64(s1c7_ciphertext_base64);
	if (ciphertext == NULL)
		munit_error("bytes_from_base64");
	struct bytes *key = bytes_from_str(s1c7_key);
	struct bytes *empty = bytes_from_str("");
	if (key == NULL || empty == NULL)
		munit_error("bytes_from_str");

	/* when NULL is given */
	munit_assert_null(aes_128_ecb_encrypt(NULL, key));
	munit_assert_null(aes_128_ecb_encrypt(ciphertext, NULL));
	/* when the key has not a valid length */
	munit_assert_null(aes_128_ecb_encrypt(ciphertext, empty));

	bytes_free(empty);
	bytes_free(key);
	bytes_free(ciphertext);
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
	struct bytes *plaintext = bytes_from_str(s1c7_plaintext);
	struct bytes *key = bytes_from_str(s1c7_key);
	struct bytes *empty = bytes_from_str("");
	if (plaintext == NULL || key == NULL || empty == NULL)
		munit_error("bytes_from_str");

	/* when NULL is given */
	munit_assert_null(aes_128_ecb_decrypt(NULL, key));
	munit_assert_null(aes_128_ecb_decrypt(plaintext, NULL));
	/* when the key has not a valid length */
	munit_assert_null(aes_128_ecb_decrypt(plaintext, empty));

	bytes_free(empty);
	bytes_free(key);
	bytes_free(plaintext);
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
MunitTest test_aes_suite_tests[] = {
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
