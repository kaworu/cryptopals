/*
 * test_break_aes.c
 */
#include "munit.h"
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

/* The test suite. */
MunitTest test_break_aes_suite_tests[] = {
	{ "aes_128_ecb_detect-0",  test_aes_128_ecb_detect_0,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_ecb_detect-1",  test_aes_128_ecb_detect_1,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};