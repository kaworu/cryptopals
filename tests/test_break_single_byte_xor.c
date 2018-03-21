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
	uint8_t key = 0;
	double prob = 0;

	struct bytes *buf = bytes_from_hex(ciphertext);
	if (buf == NULL)
		munit_error("bytes_from_hex");

	struct bytes *decrypted = break_single_byte_xor(buf, &key, &prob);
	munit_assert_not_null(decrypted);
	munit_assert_size(decrypted->len, ==, strlen(expected));
	munit_assert_memory_equal(decrypted->len, decrypted->data, expected);
	munit_assert_double(prob, >, 0.80);
	munit_assert_uint8(key, ==, (uint8_t)'X');

	bytes_free(decrypted);
	bytes_free(buf);
	return (MUNIT_OK);
}


/* Set 1 / Challenge 4 */
static MunitResult
test_break_single_byte_xor_2(const MunitParameter *params, void *data)
{
	const char *expected = "Now that the party is jumping\n";
	struct bytes *found = NULL;
	uint8_t fkey = 0;
	double fprob = 0;

	for (size_t i = 0; i < (sizeof(s1c4data) / sizeof(*s1c4data)); i++) {
		const char *ciphertext = s1c4data[i];
		struct bytes *buf = bytes_from_hex(ciphertext);
		if (buf == NULL)
			munit_error("bytes_from_hex");

		double prob = 0;
		uint8_t key = 0;
		struct bytes *decrypted = break_single_byte_xor(buf, &key, &prob);
		munit_assert_not_null(decrypted);

		if (prob > fprob) {
			bytes_free(found);
			found = decrypted;
			fkey  = key;
			fprob = prob;
		} else {
			bytes_free(decrypted);
		}
		bytes_free(buf);
	}

	munit_assert_not_null(found);
	munit_assert_size(found->len, ==, strlen(expected));
	munit_assert_memory_equal(found->len, found->data, expected);
	munit_assert_double(fprob, >, 0.80);
	munit_assert_uint8(fkey, ==, (uint8_t)'5');

	bytes_free(found);
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
