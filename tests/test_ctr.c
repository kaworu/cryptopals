/*
 * test_ctr.c
 */
#include "munit.h"
#include "helpers.h"
#include "nope.h"
#include "ctr.h"
#include "test_ctr.h"


/* Error conditions */
static MunitResult
test_aes_128_ctr_encrypt_0(const MunitParameter *params, void *data)
{
	struct bytes *plaintext = bytes_from_str(s3c18_plaintext);
	struct bytes *key = bytes_from_str(s3c18_key);
	struct bytes *one_byte = bytes_from_str("x");
	if (plaintext == NULL || key == NULL || one_byte == NULL)
		munit_error("bytes_from_str");
	const uint64_t nonce = rand_uint64();

	/* when NULL is given */
	munit_assert_null(aes_128_ctr_encrypt(NULL, key, nonce));
	munit_assert_null(aes_128_ctr_encrypt(plaintext, NULL, nonce));
	/* when the key has not a valid length */
	munit_assert_null(aes_128_ctr_encrypt(plaintext, one_byte, nonce));

	bytes_free(one_byte);
	bytes_free(key);
	bytes_free(plaintext);
	return (MUNIT_OK);
}


static MunitResult
test_aes_128_ctr_encrypt_1(const MunitParameter *params, void *data)
{
	struct bytes *expected = bytes_from_base64(s3c18_ciphertext_base64);
	if (expected == NULL)
		munit_error("bytes_from_base64");
	struct bytes *key = bytes_from_str(s3c18_key);
	struct bytes *plaintext = bytes_from_str(s3c18_plaintext);
	if (key == NULL || plaintext == NULL)
		munit_error("bytes_from_str");
	const uint64_t nonce = s3c18_nonce;

	struct bytes *ciphertext = aes_128_ctr_encrypt(plaintext, key, nonce);
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
test_aes_128_ctr_decrypt_0(const MunitParameter *params, void *data)
{
	struct bytes *key = bytes_from_str(s3c18_key);
	struct bytes *one_byte = bytes_from_str("x");
	if (key == NULL || one_byte == NULL)
		munit_error("bytes_from_str");
	struct bytes *ciphertext = bytes_from_base64(s3c18_ciphertext_base64);
	if (ciphertext == NULL)
		munit_error("bytes_from_base64");
	const uint64_t nonce = rand_uint64();

	/* when NULL is given */
	munit_assert_null(aes_128_ctr_decrypt(NULL, key, nonce));
	munit_assert_null(aes_128_ctr_decrypt(ciphertext, NULL, nonce));
	/* when the key has not a valid length */
	munit_assert_null(aes_128_ctr_decrypt(ciphertext, one_byte, nonce));

	bytes_free(one_byte);
	bytes_free(key);
	bytes_free(ciphertext);
	return (MUNIT_OK);
}


/* Set 3 / Challenge 18 */
static MunitResult
test_aes_128_ctr_decrypt_1(const MunitParameter *params, void *data)
{
	struct bytes *ciphertext = bytes_from_base64(s3c18_ciphertext_base64);
	if (ciphertext == NULL)
		munit_error("bytes_from_base64");
	struct bytes *key = bytes_from_str(s3c18_key);
	if (key == NULL)
		munit_error("bytes_from_str");
	const uint64_t nonce = s3c18_nonce;

	struct bytes *plaintext = aes_128_ctr_decrypt(ciphertext, key, nonce);
	munit_assert_not_null(plaintext);
	munit_assert_size(plaintext->len, ==, strlen(s3c18_plaintext));
	munit_assert_memory_equal(plaintext->len, plaintext->data, s3c18_plaintext);

	bytes_free(plaintext);
	bytes_free(key);
	bytes_free(ciphertext);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_ctr_suite_tests[] = {
	{ "aes_128_ctr_encrypt-0", test_aes_128_ctr_encrypt_0, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_ctr_encrypt-1", test_aes_128_ctr_encrypt_1, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_ctr_decrypt-0", test_aes_128_ctr_decrypt_0, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_ctr_decrypt-1", test_aes_128_ctr_decrypt_1, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
