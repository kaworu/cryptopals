/*
 * test_break_single_byte_xor.c
 */
#include "munit.h"
#include "break_single_byte_xor.h"
#include "test_break_single_byte_xor.h"


/* Set 1 / Challenge 3 */
static MunitResult
test_break_single_byte_xor_1(const MunitParameter *params, void *data)
{
	const char *ciphertext =
	    "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
	const char *expected = "Cooking MC's like a pound of bacon";
	struct bytes *key = NULL;
	double score = 0;

	struct bytes *buf = bytes_from_hex(ciphertext);
	if (buf == NULL)
		munit_error("bytes_from_hex");

	struct bytes *decrypted = break_single_byte_xor(buf, &key, &score);
	munit_assert_not_null(decrypted);
	munit_assert_size(decrypted->len, ==, strlen(expected));
	munit_assert_memory_equal(decrypted->len, decrypted->data, expected);
	munit_assert_not_null(key);
	munit_assert_size(key->len, ==, 1);
	munit_assert_uint8(key->data[0], ==, (uint8_t)'X');
	munit_assert_double(score, >, 0.80);

	bytes_free(decrypted);
	bytes_free(key);
	bytes_free(buf);
	return (MUNIT_OK);
}


/* Set 1 / Challenge 4 */
static MunitResult
test_break_single_byte_xor_2(const MunitParameter *params, void *data)
{
	const char *expected = "Now that the party is jumping\n";
	struct bytes *decrypted = NULL, *key = NULL;
	double score = 0;

	for (size_t i = 0; i < (sizeof(s1c4data) / sizeof(*s1c4data)); i++) {
		struct bytes *idecrypted = NULL, *ikey = NULL;
		double iscore = 0;

		const char *ciphertext = s1c4data[i];
		struct bytes *buf = bytes_from_hex(ciphertext);
		if (buf == NULL)
			munit_error("bytes_from_hex");

		idecrypted = break_single_byte_xor(buf, &ikey, &iscore);
		munit_assert_not_null(idecrypted);
		munit_assert_not_null(ikey);

		if (iscore > score) {
			bytes_free(decrypted);
			decrypted = idecrypted;
			bytes_free(key);
			key = ikey;
			score = iscore;
		} else {
			bytes_free(idecrypted);
			bytes_free(ikey);
		}
		bytes_free(buf);
	}

	munit_assert_not_null(decrypted);
	munit_assert_size(decrypted->len, ==, strlen(expected));
	munit_assert_memory_equal(decrypted->len, decrypted->data, expected);
	munit_assert_not_null(key);
	munit_assert_size(key->len, ==, 1);
	munit_assert_uint8(key->data[0], ==, (uint8_t)'5');
	munit_assert_double(score, >, 0.80);

	bytes_free(decrypted);
	bytes_free(key);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_break_single_byte_xor_suite_tests[] = {
	{ "break_single_byte_xor-1", test_break_single_byte_xor_1, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "break_single_byte_xor-2", test_break_single_byte_xor_2, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
