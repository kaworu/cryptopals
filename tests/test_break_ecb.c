/*
 * test_break_ecb.c
 */
#include "munit.h"
#include "helpers.h"
#include "break_ecb.h"
#include "test_break_ecb.h"


/* Error conditions */
static MunitResult
test_ecb_detect_0(const MunitParameter *params, void *data)
{
	double score = 0;
	struct bytes *empty = bytes_from_str("");
	if (empty == NULL)
		munit_error("bytes_from_str");

	munit_assert_int(ecb_detect(NULL, &score), ==, -1);
	munit_assert_double(score, ==, 0);
	munit_assert_int(ecb_detect(empty, NULL), ==, -1);

	bytes_free(empty);
	return (MUNIT_OK);
}


/* Set 1 / Challenge 8 */
static MunitResult
test_ecb_detect_1(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < (sizeof(s1c8_data) / sizeof(*s1c8_data)); i++) {
		double score = 0;
		struct bytes *ciphertext = bytes_from_hex(s1c8_data[i]);
		if (ciphertext == NULL)
			munit_error("bytes_from_hex");

		int ret = ecb_detect(ciphertext, &score);
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
test_ecb_cbc_detect_0(const MunitParameter *params, void *data)
{
	struct bytes *too_small = bytes_zeroed(4 * 16 - 1);
	if (too_small == NULL)
		munit_error("bytes_zeroed");

	munit_assert_int(ecb_cbc_detect(NULL), ==, -1);
	munit_assert_int(ecb_cbc_detect(too_small), ==, -1);

	bytes_free(too_small);
	return (MUNIT_OK);
}


/* Set 2 / Challenge 11 */
static MunitResult
test_ecb_cbc_detect_1(const MunitParameter *params, void *data)
{
	int ecb = 0;
	struct bytes *jibber = NULL;
	struct bytes *input = ecb_cbc_detect_input();
	if (input == NULL)
		munit_error("ecb_cbc_detect_input");

	for (size_t i = 0; i < 100; i++) {
		jibber = ecb_cbc_encryption_oracle(input, &ecb);
		if (jibber == NULL)
			munit_error("ecb_cbc_encryption_oracle");
		munit_assert_int(ecb_cbc_detect(jibber), ==, ecb);
		bytes_free(jibber);
	}

	bytes_free(input);
	return (MUNIT_OK);
}


/* Set 2 / Challenge 12 */
static MunitResult
test_ecb_baat_breaker12(const MunitParameter *params, void *data)
{
	struct bytes *recovered = NULL;
	struct bytes *key = bytes_randomized(16);
	if (key == NULL)
		munit_error("bytes_randomized");
	struct bytes *message = bytes_from_base64(s2c12_message_base64);
	if (message == NULL)
		munit_error("bytes_from_base64");

	recovered = ecb_byte_at_a_time_breaker12(message, key);
	munit_assert_not_null(recovered);
	munit_assert_size(recovered->len, ==, message->len);
	munit_assert_memory_equal(message->len, message->data, recovered->data);

	bytes_free(recovered);
	bytes_free(message);
	bytes_free(key);
	return (MUNIT_OK);
}


/* Testing the Set 2 / Challenge 13 Oracle */
static MunitResult
test_ecb_cnp_oracle(const MunitParameter *params, void *data)
{
	size_t count = 0;
	struct cookie *profile = NULL;
	const struct cookie_kv *kv = NULL;

	const char *email = "foo@bar.com";
	struct bytes *key = bytes_randomized(16);
	if (key == NULL)
		munit_error("bytes_randomized");
	struct bytes *ciphertext = ecb_cut_and_paste_profile_for(email, key);
	munit_assert_not_null(ciphertext);
	profile = ecb_cut_and_paste_profile(ciphertext, key);

	munit_assert_not_null(profile);
	if (cookie_count(profile, &count) != 0)
		munit_error("cookie_count");
	munit_assert_size(count, ==, 3);

	kv = cookie_at(profile, 0);
	munit_assert_not_null(kv);
	munit_assert_string_equal(cookie_kv_key(kv), "email");
	munit_assert_string_equal(cookie_kv_value(kv), "foo@bar.com");

	kv = cookie_at(profile, 1);
	munit_assert_not_null(kv);
	munit_assert_string_equal(cookie_kv_key(kv), "uid");
	munit_assert_string_equal(cookie_kv_value(kv), "10");

	kv = cookie_at(profile, 2);
	munit_assert_not_null(kv);
	munit_assert_string_equal(cookie_kv_key(kv), "role");
	munit_assert_string_equal(cookie_kv_value(kv), "user");

	cookie_free(profile);
	bytes_free(ciphertext);
	bytes_free(key);
	return (MUNIT_OK);
}


/* Set 2 / Challenge 13 */
static MunitResult
test_ecb_cnp_breaker(const MunitParameter *params, void *data)
{
	struct bytes *key = bytes_randomized(16);
	if (key == NULL)
		munit_error("bytes_randomized");

	struct bytes *ciphertext = ecb_cut_and_paste_profile_breaker(key);
	munit_assert_not_null(ciphertext);
	struct cookie *profile = ecb_cut_and_paste_profile(ciphertext, key);
	munit_assert_not_null(profile);
	const struct cookie_kv *kv = cookie_get(profile, "role");
	munit_assert_not_null(kv);
	munit_assert_string_equal(cookie_kv_value(kv), "admin");

	cookie_free(profile);
	bytes_free(ciphertext);
	bytes_free(key);
	return (MUNIT_OK);
}


/* Set 2 / Challenge 14 */
static MunitResult
test_ecb_baat_breaker14(const MunitParameter *params, void *data)
{

	struct bytes *recovered = NULL;
	struct bytes *key = bytes_randomized(16);
	struct bytes *prefix = bytes_randomized(munit_rand_int_range(16, 16 * 64));
	if (key == NULL || prefix == NULL)
		munit_error("bytes_randomized");
	struct bytes *message = bytes_from_base64(s2c12_message_base64);
	if (message == NULL)
		munit_error("bytes_from_base64");

	recovered = ecb_byte_at_a_time_breaker14(prefix, message, key);
	munit_assert_not_null(recovered);
	munit_assert_size(recovered->len, ==, message->len);
	munit_assert_memory_equal(message->len, message->data, recovered->data);

	bytes_free(recovered);
	bytes_free(message);
	bytes_free(prefix);
	bytes_free(key);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_break_ecb_suite_tests[] = {
	{ "ecb_detect-0",              test_ecb_detect_0,       NULL,        NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "ecb_detect-1",              test_ecb_detect_1,       NULL,        NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "ecb_cbc_detect-0",          test_ecb_cbc_detect_0,   NULL,        NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "ecb_cbc_detect-1",          test_ecb_cbc_detect_1,   srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "ecb_byte_at_a_time-simple", test_ecb_baat_breaker12, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "ecb_cut_and_paste-0",       test_ecb_cnp_oracle,     srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "ecb_cut_and_paste-1",       test_ecb_cnp_breaker,    srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "ecb_byte_at_a_time-harder", test_ecb_baat_breaker14, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
