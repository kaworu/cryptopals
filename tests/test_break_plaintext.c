/*
 * test_break_plaintext.c
 */
#include "munit.h"
#include "break_plaintext.h"
#include "test_break_plaintext.h"


static MunitResult
test_english_char_freq(const MunitParameter *params, void *data)
{
	struct bytes *english = bytes_from_str(english_text);
	struct bytes *german  = bytes_from_str(german_text);
	struct bytes *random  = bytes_from_base64(random_base64);
	if (english == NULL || german == NULL)
		munit_error("bytes_from_str");
	if (random == NULL)
		munit_error("bytes_from_base64");

	double eng  = english_char_freq(english);
	double ger  = english_char_freq(german);
	double rand = english_char_freq(random);
	munit_assert_double(eng, >, ger);
	munit_assert_double(ger, >, rand);

	bytes_free(random);
	bytes_free(german);
	bytes_free(english);
	return (MUNIT_OK);
}


static MunitResult
test_english_word_lengths_freq(const MunitParameter *params, void *data)
{
	struct bytes *english = bytes_from_str(english_text);
	struct bytes *german  = bytes_from_str(german_text);
	struct bytes *random  = bytes_from_base64(random_base64);
	if (english == NULL || german == NULL)
		munit_error("bytes_from_str");
	if (random == NULL)
		munit_error("bytes_from_base64");

	double eng  = english_word_lengths_freq(english);
	double ger  = english_word_lengths_freq(german);
	double rand = english_word_lengths_freq(random);
	munit_assert_double(eng, >, ger);
	munit_assert_double(ger, >, rand);

	bytes_free(random);
	bytes_free(german);
	bytes_free(english);
	return (MUNIT_OK);
}


static MunitResult
test_looks_like_english(const MunitParameter *params, void *data)
{
	struct bytes *english = bytes_from_str(english_text);
	struct bytes *german  = bytes_from_str(german_text);
	struct bytes *random  = bytes_from_base64(random_base64);
	if (english == NULL || german == NULL)
		munit_error("bytes_from_str");
	if (random == NULL)
		munit_error("bytes_from_base64");

	double eng  = looks_like_english(english);
	double ger  = looks_like_english(german);
	double rand = looks_like_english(random);
	munit_assert_double(eng, >, ger);
	munit_assert_double(ger, >, rand);

	bytes_free(random);
	bytes_free(german);
	bytes_free(english);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_break_plaintext_suite_tests[] = {
	{ "english_char_freq",         test_english_char_freq,         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "english_word_lengths_freq", test_english_word_lengths_freq, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "looks_like_english",        test_looks_like_english,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
