/*
 * test_break_repeating_key_xor.c
 */
#include "munit.h"
#include "break_repeating_key_xor.h"
#include "test_break_repeating_key_xor.h"


/* Error conditions */
static MunitResult
test_break_repeating_key_xor_0(const MunitParameter *params, void *data)
{
	struct bytes *empty = bytes_from_str("");
	if (empty == NULL)
		munit_error("bytes_from_str");

	/* when NULL is given */
	munit_assert_null(break_repeating_key_xor(NULL, NULL, NULL));
	/* when an empty buffer is given */
	munit_assert_null(break_repeating_key_xor(empty, NULL, NULL));

	bytes_free(empty);
	return (MUNIT_OK);
}


/* Set 1 / Challenge 6 */
static MunitResult
test_break_repeating_key_xor_1(const MunitParameter *params, void *data)
{
	struct bytes *ciphertext = bytes_from_base64(s1c6_ciphertext_base64);
	if (ciphertext == NULL)
		munit_error("bytes_from_base64");

	struct bytes *key = NULL;
	double score = 0.0;
	struct bytes *decrypted = break_repeating_key_xor(ciphertext, &key, &score);

	munit_assert_not_null(decrypted);
	munit_assert_size(decrypted->len, ==, strlen(s1c6_plaintext));
	munit_assert_memory_equal(decrypted->len, decrypted->data, s1c6_plaintext);

	munit_assert_not_null(key);
	munit_assert_size(key->len, ==, strlen(s1c6_key));
	munit_assert_memory_equal(key->len, key->data, s1c6_key);

	munit_assert_double(score, >, 0.66);

	bytes_free(key);
	bytes_free(decrypted);
	bytes_free(ciphertext);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_break_repeating_key_xor_suite_tests[] = {
	{ "break_repeating_key_xor-0", test_break_repeating_key_xor_0, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "break_repeating_key_xor-1", test_break_repeating_key_xor_1, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
