/*
 * test_cbc.c
 */
#include "munit.h"
#include "helpers.h"
#include "nope.h"
#include "cbc.h"

#include "test_cbc.h"


/* Error conditions */
static MunitResult
test_nope_cbc_encrypt_0(const MunitParameter *params, void *data)
{
	struct bytes *plaintext = bytes_randomized(42);
	struct bytes *key = bytes_randomized(nope_keylength());
	struct bytes *one_byte = bytes_randomized(1);
	struct bytes *iv = bytes_randomized(nope_blocksize());
	if (plaintext == NULL || key == NULL || one_byte == NULL || iv == NULL)
		munit_error("bytes_randomized");

	/* when NULL is given */
	munit_assert_null(nope_cbc_encrypt(NULL, key, iv));
	munit_assert_null(nope_cbc_encrypt(NULL, NULL, iv));
	munit_assert_null(nope_cbc_encrypt(plaintext, key, NULL));
	munit_assert_null(nope_cbc_encrypt(plaintext, NULL, NULL));
	/* when the iv has not a valid length */
	munit_assert_null(nope_cbc_encrypt(plaintext, key, one_byte));
	munit_assert_null(nope_cbc_encrypt(plaintext, NULL, one_byte));

	bytes_free(iv);
	bytes_free(one_byte);
	bytes_free(key);
	bytes_free(plaintext);
	return (MUNIT_OK);
}


static MunitResult
test_nope_cbc_encrypt_1(const MunitParameter *params, void *data)
{
	struct bytes *iv = bytes_from_str(
		    "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01");
	struct bytes *plaintext = bytes_from_str(
		    "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02"
		    "\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04"
		    "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01");
	struct bytes *expected = bytes_from_str(
		    "\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03"
		    "\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07"
		    "\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06"
		    /* the padding is a full block of 0x10, XOR'ed with the
		       previous ciphertext block */
		    "\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16");
	if (iv == NULL || plaintext == NULL || expected == NULL)
		munit_error("bytes_from_str");

	struct bytes *key = bytes_randomized(nope_keylength());
	if (key == NULL)
		munit_error("bytes_randomized");

	struct bytes *ciphertext = nope_cbc_encrypt(plaintext, key, iv);
	munit_assert_not_null(ciphertext);
	munit_assert_size(ciphertext->len, ==, expected->len);
	munit_assert_memory_equal(ciphertext->len, ciphertext->data,
		    expected->data);

	bytes_free(ciphertext);
	bytes_free(key);
	bytes_free(expected);
	bytes_free(plaintext);
	bytes_free(iv);
	return (MUNIT_OK);
}


/* Error conditions */
static MunitResult
test_nope_cbc_decrypt_0(const MunitParameter *params, void *data)
{
	struct bytes *ciphertext = bytes_randomized(42);
	struct bytes *key = bytes_randomized(nope_keylength());
	struct bytes *one_byte = bytes_randomized(1);
	struct bytes *iv = bytes_randomized(nope_blocksize());
	if (ciphertext == NULL || key == NULL || one_byte == NULL || iv == NULL)
		munit_error("bytes_randomized");

	/* when NULL is given */
	munit_assert_null(nope_cbc_decrypt(NULL, key, iv));
	munit_assert_null(nope_cbc_decrypt(NULL, NULL, iv));
	munit_assert_null(nope_cbc_decrypt(ciphertext, key, NULL));
	munit_assert_null(nope_cbc_decrypt(ciphertext, NULL, NULL));
	/* when the iv has not a valid length */
	munit_assert_null(nope_cbc_decrypt(ciphertext, key, one_byte));
	munit_assert_null(nope_cbc_decrypt(ciphertext, NULL, one_byte));

	bytes_free(iv);
	bytes_free(one_byte);
	bytes_free(key);
	bytes_free(ciphertext);
	return (MUNIT_OK);
}


static MunitResult
test_nope_cbc_decrypt_1(const MunitParameter *params, void *data)
{
	struct bytes *iv = bytes_from_str(
		    "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01");
	struct bytes *ciphertext = bytes_from_str(
		    "\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03"
		    "\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07"
		    "\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06"
		    /* the padding is a full block of 0x10, XOR'ed with the
		       previous ciphertext block */
		    "\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16");
	struct bytes *expected = bytes_from_str(
		    "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02"
		    "\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04"
		    "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01");
	if (iv == NULL || ciphertext == NULL || expected == NULL)
		munit_error("bytes_from_str");

	struct bytes *key = bytes_randomized(nope_keylength());
	if (key == NULL)
		munit_error("bytes_randomized");

	struct bytes *plaintext = nope_cbc_decrypt(ciphertext, key, iv);
	munit_assert_not_null(plaintext);
	munit_assert_size(plaintext->len, ==, expected->len);
	munit_assert_memory_equal(plaintext->len, plaintext->data,
		    expected->data);

	bytes_free(plaintext);
	bytes_free(key);
	bytes_free(expected);
	bytes_free(ciphertext);
	bytes_free(iv);
	return (MUNIT_OK);
}


/* Error conditions */
static MunitResult
test_aes_128_cbc_encrypt_0(const MunitParameter *params, void *data)
{
	struct bytes *plaintext = bytes_from_str(s2c10_plaintext);
	struct bytes *key = bytes_from_str(s2c10_key);
	struct bytes *one_byte = bytes_from_str("x");
	if (plaintext == NULL || key == NULL || one_byte == NULL)
		munit_error("bytes_from_str");
	struct bytes *iv = bytes_zeroed(16);
	if (iv == NULL)
		munit_error("bytes_zeroed");

	/* when NULL is given */
	munit_assert_null(aes_128_cbc_encrypt(NULL, key, iv));
	munit_assert_null(aes_128_cbc_encrypt(plaintext, NULL, iv));
	munit_assert_null(aes_128_cbc_encrypt(plaintext, key, NULL));
	/* when the key has not a valid length */
	munit_assert_null(aes_128_cbc_encrypt(plaintext, one_byte, iv));
	/* when the iv has not a valid length */
	munit_assert_null(aes_128_cbc_encrypt(plaintext, key, one_byte));

	bytes_free(iv);
	bytes_free(one_byte);
	bytes_free(key);
	bytes_free(plaintext);
	return (MUNIT_OK);
}


static MunitResult
test_aes_128_cbc_encrypt_1(const MunitParameter *params, void *data)
{
	struct bytes *expected = bytes_from_base64(s2c10_ciphertext_base64);
	if (expected == NULL)
		munit_error("bytes_from_base64");
	struct bytes *key = bytes_from_str(s2c10_key);
	struct bytes *plaintext = bytes_from_str(s2c10_plaintext);
	if (key == NULL || plaintext == NULL)
		munit_error("bytes_from_str");
	struct bytes *iv = bytes_zeroed(16);
	if (iv == NULL)
		munit_error("bytes_zeroed");

	struct bytes *ciphertext = aes_128_cbc_encrypt(plaintext, key, iv);
	munit_assert_not_null(ciphertext);
	munit_assert_size(ciphertext->len, ==, expected->len);
	munit_assert_memory_equal(ciphertext->len, ciphertext->data,
		    expected->data);

	bytes_free(iv);
	bytes_free(ciphertext);
	bytes_free(plaintext);
	bytes_free(key);
	bytes_free(expected);
	return (MUNIT_OK);
}


/* Error conditions */
static MunitResult
test_aes_128_cbc_decrypt_0(const MunitParameter *params, void *data)
{
	struct bytes *ciphertext = bytes_from_base64(s2c10_ciphertext_base64);
	if (ciphertext == NULL)
		munit_error("bytes_from_base64");
	struct bytes *key = bytes_from_str(s2c10_key);
	struct bytes *one_byte = bytes_from_str("x");
	struct bytes *empty = bytes_from_str("");
	if (key == NULL || one_byte == NULL || empty == NULL)
		munit_error("bytes_from_str");
	struct bytes *iv = bytes_zeroed(16);
	if (iv == NULL)
		munit_error("bytes_zeroed");

	/* when NULL is given */
	munit_assert_null(aes_128_cbc_decrypt(NULL, key, iv));
	munit_assert_null(aes_128_cbc_decrypt(ciphertext, NULL, iv));
	munit_assert_null(aes_128_cbc_decrypt(ciphertext, key, NULL));
	/* when the key length is invalid */
	munit_assert_null(aes_128_cbc_decrypt(ciphertext, one_byte, iv));
	/* when the iv length is invalid */
	munit_assert_null(aes_128_cbc_decrypt(ciphertext, key, one_byte));
	/* when the ciphertext length is invalid */
	munit_assert_null(aes_128_cbc_decrypt(one_byte, key, iv));
	munit_assert_null(aes_128_cbc_decrypt(empty, key, iv));

	bytes_free(iv);
	bytes_free(empty);
	bytes_free(one_byte);
	bytes_free(key);
	bytes_free(ciphertext);
	return (MUNIT_OK);
}


/* Set 2 / Challenge 10 */
static MunitResult
test_aes_128_cbc_decrypt_1(const MunitParameter *params, void *data)
{
	struct bytes *ciphertext = bytes_from_base64(s2c10_ciphertext_base64);
	if (ciphertext == NULL)
		munit_error("bytes_from_base64");
	struct bytes *key = bytes_from_str(s2c10_key);
	if (key == NULL)
		munit_error("bytes_from_str");
	struct bytes *iv = bytes_zeroed(16);
	if (iv == NULL)
		munit_error("bytes_zeroed");

	struct bytes *plaintext = aes_128_cbc_decrypt(ciphertext, key, iv);
	munit_assert_not_null(plaintext);
	munit_assert_size(plaintext->len, ==, strlen(s2c10_plaintext));
	munit_assert_memory_equal(plaintext->len, plaintext->data, s2c10_plaintext);

	bytes_free(plaintext);
	bytes_free(iv);
	bytes_free(key);
	bytes_free(ciphertext);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_cbc_suite_tests[] = {
	{ "nope_cbc_encrypt-0", test_nope_cbc_encrypt_0, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nope_cbc_encrypt-1", test_nope_cbc_encrypt_1, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nope_cbc_decrypt-0", test_nope_cbc_decrypt_0, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nope_cbc_decrypt-1", test_nope_cbc_decrypt_1, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_cbc_encrypt-0", test_aes_128_cbc_encrypt_0, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_cbc_encrypt-1", test_aes_128_cbc_encrypt_1, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_cbc_decrypt-0", test_aes_128_cbc_decrypt_0, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_cbc_decrypt-1", test_aes_128_cbc_decrypt_1, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
