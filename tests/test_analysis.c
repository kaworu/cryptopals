/*
 * test_analysis.c
 *
 */
#include <stdlib.h>

#include "munit.h"
#include "analysis.h"
#include "test_analysis.h"


/* text taken from http://norvig.com/mayzner.html */
static MunitResult
test_analysis_looks_like_english(const MunitParameter *params, void *data)
{
	const char *text = "I culled a corpus of 20,000 words from a variety of"
	    " sources, e.g., newspapers, magazines, books, etc. For each source"
	    " selected, a starting place was chosen at random. In proceeding"
	    " forward from this point, all three, four, five, six, and"
	    " seven-letter words were recorded until a total of 200 words had been"
	    " selected. This procedure was duplicated 100 times, each time with a"
	    " different source, thus yielding a grand total of 20,000 words. This"
	    " sample broke down as follows: three-letter words, 6,807 tokens, 187"
	    " types; four-letter words, 5,456 tokens, 641 types; five-letter"
	    " words, 3,422 tokens, 856 types; six-letter words, 2,264 tokens, 868"
	    " types; seven-letter words, 2,051 tokens, 924 types. I then proceeded"
	    " to construct tables that showed the frequency counts for three,"
	    " four, five, six, and seven-letter words, but most importantly,"
	    " broken down by word length and letter position, which had never"
	    " been done before to my knowledge.";

	struct bytes *buf = bytes_from_str(text);
	if (buf == NULL)
		munit_error("bytes_from_str");

	const double prob = analysis_looks_like_english(buf);
	munit_assert_double(prob, >, 0.80);

	bytes_free(buf);
	return (MUNIT_OK);
}


/* Set 1 / Challenge 3 */
static MunitResult
test_analysis_single_byte_xor_1(const MunitParameter *params, void *data)
{
	const char *ciphertext =
	    "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
	const char *expected = "Cooking MC's like a pound of bacon";
	uint8_t key = 0;
	double prob = 0;

	struct bytes *buf = bytes_from_hex(ciphertext);
	if (buf == NULL)
		munit_error("bytes_from_hex");

	struct bytes *decrypted = analysis_single_byte_xor(buf, &key, &prob);
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
test_analysis_single_byte_xor_2(const MunitParameter *params, void *data)
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
		struct bytes *decrypted = analysis_single_byte_xor(buf, &key, &prob);
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
MunitTest test_analysis_suite_tests[] = {
	{ "analysis_looks_like_english", test_analysis_looks_like_english, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "analysis_single_byte_xor-1",  test_analysis_single_byte_xor_1,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "analysis_single_byte_xor-2",  test_analysis_single_byte_xor_2,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
