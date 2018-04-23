/*
 * test_break_aes.c
 */
#include "munit.h"
#include "helpers.h"
#include "break_aes.h"
#include "test_break_aes.h"


/* Error conditions */
static MunitResult
test_aes_128_ecb_detect_0(const MunitParameter *params, void *data)
{
	double score = 0;
	struct bytes *empty = bytes_from_str("");
	if (empty == NULL)
		munit_error("bytes_from_str");

	munit_assert_int(aes_128_ecb_detect(NULL, &score), ==, -1);
	munit_assert_double(score, ==, 0);
	munit_assert_int(aes_128_ecb_detect(empty, NULL), ==, -1);

	bytes_free(empty);
	return (MUNIT_OK);
}


/* Set 1 / Challenge 8 */
static MunitResult
test_aes_128_ecb_detect_1(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < (sizeof(s1c8_data) / sizeof(*s1c8_data)); i++) {
		double score = 0;
		struct bytes *ciphertext = bytes_from_hex(s1c8_data[i]);
		if (ciphertext == NULL)
			munit_error("bytes_from_hex");

		int ret = aes_128_ecb_detect(ciphertext, &score);
		munit_assert_int(ret, ==, 0); /* success */
		if (i == s1c8_jackpot)
			munit_assert_double(score, >, 0);
		else
			munit_assert_double(score, ==, 0);

		bytes_free(ciphertext);
	}

	return (MUNIT_OK);
}


/* Error conditions */
static MunitResult
test_aes_128_ecb_cbc_detect_0(const MunitParameter *params, void *data)
{
	struct bytes *too_small = bytes_zeroed(4 * 16 - 1);
	if (too_small == NULL)
		munit_error("bytes_zeroed");

	munit_assert_int(aes_128_ecb_cbc_detect(NULL), ==, -1);
	munit_assert_int(aes_128_ecb_cbc_detect(too_small), ==, -1);

	bytes_free(too_small);
	return (MUNIT_OK);
}


/* Set 2 / Challenge 11 */
static MunitResult
test_aes_128_ecb_cbc_detect_1(const MunitParameter *params, void *data)
{
	int ecb = 0;
	struct bytes *jibber = NULL;
	struct bytes *input = aes_128_ecb_cbc_detect_input();
	if (input == NULL)
		munit_error("aes_128_ecb_cbc_detect_input");

	for (size_t i = 0; i < 100; i++) {
		jibber = aes_128_ecb_cbc_encryption_oracle(input, &ecb);
		if (jibber == NULL)
			munit_error("aes_128_ecb_cbc_encryption_oracle");
		munit_assert_int(aes_128_ecb_cbc_detect(jibber), ==, ecb);
		bytes_free(jibber);
	}

	bytes_free(input);
	return (MUNIT_OK);
}


/* Set 2 / Challenge 12 */
static MunitResult
test_aes_128_ecb_baat_breaker(const MunitParameter *params, void *data)
{
	struct bytes *key = bytes_randomized(16);
	if (key == NULL)
		munit_error("bytes_randomized");
	struct bytes *message = bytes_from_base64(s2c12_message_base64);
	if (message == NULL)
		munit_error("bytes_from_base64");

	struct bytes *recovered =
		    aes_128_ecb_byte_at_a_time_breaker(message, key);
	munit_assert_not_null(recovered);
	munit_assert_size(recovered->len, ==, message->len);
	munit_assert_memory_equal(message->len, message->data, recovered->data);

	bytes_free(recovered);
	bytes_free(message);
	bytes_free(key);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_break_aes_suite_tests[] = {
	{ "aes_128_ecb_detect-0",     test_aes_128_ecb_detect_0,     NULL,        NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_ecb_detect-1",     test_aes_128_ecb_detect_1,     NULL,        NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_ecb_cbc_detect-0", test_aes_128_ecb_cbc_detect_0, NULL,        NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_ecb_cbc_detect-1", test_aes_128_ecb_cbc_detect_1, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_ecb_baat_breaker", test_aes_128_ecb_baat_breaker, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
