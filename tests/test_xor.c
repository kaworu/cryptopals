/*
 * test_xor.c
 */
#include <stdlib.h>

#include "munit.h"
#include "xor.h"


/* Set 1 / Challenge 2 */
static MunitResult
test_bytes_xor(const MunitParameter *params, void *data)
{
	const char *lhs = "1c0111001f010100061a024b53535009181c";
	const char *rhs = "686974207468652062756c6c277320657965";
	const char *expected = "746865206B696420646F6E277420706C6179";

	struct bytes *buf  = bytes_from_hex(lhs);
	struct bytes *mask = bytes_from_hex(rhs);
	if (buf == NULL || mask == NULL)
		munit_error("bytes_from_hex");
	int retval = bytes_xor(buf, mask);
	munit_assert_int(retval, ==, 0);

	char *result = bytes_to_hex(buf);
	if (result == NULL)
		munit_error("bytes_to_hex");
	munit_assert_string_equal(result, expected);

	struct bytes *empty = bytes_from_str("");
	if (empty == NULL)
		munit_error("bytes_from_str");
	struct bytes *cpy = bytes_dup(buf);
	if (cpy == NULL)
		munit_error("bytes_dup");
	/* when NULL is given */
	munit_assert_int(bytes_xor(NULL, mask), ==, -1);
	munit_assert_int(bytes_xor(buf,  NULL), ==, -1);
	munit_assert_int(bytes_xor(NULL, NULL), ==, -1);
	/* when the length doesn't match */
	munit_assert_int(bytes_xor(buf, empty), ==, -1);
	/* check that buf has not be modified by error conditions */
	munit_assert_size(buf->len, ==, cpy->len);
	munit_assert_memory_equal(buf->len, buf->data, cpy->data);

	bytes_free(cpy);
	bytes_free(empty);
	free(result);
	bytes_free(mask);
	bytes_free(buf);
	return (MUNIT_OK);
}


/* Set 1 / Challenge 3 */
static MunitResult
test_repeating_key_xor_1(const MunitParameter *params, void *data)
{
	const char *plaintext = "Cooking MC's like a pound of bacon";
	const char *key = "X";
	const char *expected =
	    "1B37373331363F78151B7F2B783431333D78397828372D363C78373E783A393B3736";

	struct bytes *buf  = bytes_from_str(plaintext);
	struct bytes *kbuf = bytes_from_str(key);
	if (buf == NULL || kbuf == NULL)
		munit_error("bytes_from_str");

	int retval = repeating_key_xor(buf, kbuf);
	munit_assert_int(retval, ==, 0);

	char *ciphertext = bytes_to_hex(buf);
	if (ciphertext == NULL)
		munit_error("bytes_to_hex");
	munit_assert_string_equal(ciphertext, expected);

	free(ciphertext);
	bytes_free(kbuf);
	bytes_free(buf);
	return (MUNIT_OK);
}


/* Set 1 / Challenge 5 */
static MunitResult
test_repeating_key_xor_2(const MunitParameter *params, void *data)
{
	const char *plaintext = "Burning 'em, if you ain't quick and nimble\n"
	    "I go crazy when I hear a cymbal";
	const char *key = "ICE";
	const char *expected =
		"0B3637272A2B2E63622C2E69692A23693A2A3C6324202D623D63343C2A26226324272765272"
		"A282B2F20430A652E2C652A3124333A653E2B2027630C692B20283165286326302E27282F";

	struct bytes *buf  = bytes_from_str(plaintext);
	struct bytes *kbuf = bytes_from_str(key);
	if (buf == NULL || kbuf == NULL)
		munit_error("bytes_from_str");

	int retval = repeating_key_xor(buf, kbuf);
	munit_assert_int(retval, ==, 0);

	char *ciphertext = bytes_to_hex(buf);
	if (ciphertext == NULL)
		munit_error("bytes_to_hex");
	munit_assert_string_equal(ciphertext, expected);

	free(ciphertext);
	bytes_free(kbuf);
	bytes_free(buf);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_xor_suite_tests[] = {
	{ "bytes_xor",           test_bytes_xor,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "repeating_key_xor-1", test_repeating_key_xor_1, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "repeating_key_xor-2", test_repeating_key_xor_2, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
