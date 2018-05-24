/*
 * test_break_cbc.c
 */
#include "munit.h"
#include "helpers.h"
#include "aes.h"
#include "break_cbc.h"
#include "test_break_cbc.h"


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


/* Set 3 / Challenge 17 */
static MunitResult
test_cbc_padding(const MunitParameter *params, void *data)
{
	const size_t count = sizeof(s3c17_data) / sizeof(*s3c17_data);
	for (size_t i = 0; i < count; i++) {
		struct bytes *plaintext, *key, *iv, *ciphertext, *cracked;
		plaintext = bytes_from_base64(s3c17_data[i]);
		if (plaintext == NULL)
			munit_error("bytes_from_base64");
		key = bytes_randomized(16);
		iv  = bytes_randomized(16);
		if (key == NULL || iv == NULL)
			munit_error("bytes_randomized");
		ciphertext = aes_128_cbc_encrypt(plaintext, key, iv);
		if (ciphertext == NULL)
			munit_error("aes_128_cbc_encrypt");

		cracked = cbc_padding_breaker(ciphertext, key, iv);
		munit_assert_not_null(cracked);
		munit_assert_size(cracked->len, ==, plaintext->len);
		munit_assert_memory_equal(cracked->len,
			    cracked->data, plaintext->data);

		bytes_free(cracked);
		bytes_free(ciphertext);
		bytes_free(iv);
		bytes_free(key);
		bytes_free(plaintext);
	}

	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_break_cbc_suite_tests[] = {
	{ "cbc_bitflipping-0", test_cbc_bitflipping_0, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "cbc_bitflipping-1", test_cbc_bitflipping_1, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "cbc_padding",       test_cbc_padding,       srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
