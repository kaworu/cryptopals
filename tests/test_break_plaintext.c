/*
 * test_break_plaintext.c
 */
#include "munit.h"
#include "break_plaintext.h"
#include "test_break_plaintext.h"


static MunitResult
break_plaintext_test_helper(const MunitParameter *params, void *data,
		break_plaintext_func_t *f)
{
	struct bytes *english = bytes_from_str(english_text);
	struct bytes *german  = bytes_from_str(german_text);
	const struct bytes *random = data;
	if (english == NULL || german == NULL)
		munit_error("bytes_from_str");
	if (random == NULL)
		munit_error("bytes_from_raw");

	double english_score = 0, german_score = 0, random_score = 0;
	munit_assert_int(f(english, &english_score), ==, 0);
	munit_assert_int(f(german, &german_score),   ==, 0);
	munit_assert_int(f(random, &random_score),   ==, 0);
	munit_assert_double(english_score, >, german_score);
	munit_assert_double(german_score, >, random_score);

	/* when NULL is given */
	munit_assert_int(f(NULL, NULL),          ==, -1);
	munit_assert_int(f(NULL, &random_score), ==, -1);
	munit_assert_int(f(random, NULL),        ==, -1);

	bytes_free(german);
	bytes_free(english);
	return (MUNIT_OK);
}


static MunitResult
test_looks_like_english(const MunitParameter *params, void *data)
{
	return break_plaintext_test_helper(params, data,
		    looks_like_english);
}


static MunitResult
test_looks_like_shuffled_english(const MunitParameter *params, void *data)
{
	return break_plaintext_test_helper(params, data,
		    looks_like_shuffled_english);
}


static MunitResult
test_english_char_freq(const MunitParameter *params, void *data)
{
	return break_plaintext_test_helper(params, data,
		    english_char_freq);
}


static MunitResult
test_english_word_lengths_freq(const MunitParameter *params, void *data)
{
	return break_plaintext_test_helper(params, data,
		    english_word_lengths_freq);
}


static MunitResult
test_mostly_ascii(const MunitParameter *params, void *data)
{
	return break_plaintext_test_helper(params, data,
		    mostly_ascii);
}


/* setup functions */


static void *
setup(const MunitParameter *params, void *data)
{
	const size_t len = 1024; /* FIXME: could by #defined */
	uint8_t *buf = munit_calloc(len, sizeof(uint8_t));
	munit_rand_memory(len, buf);
	struct bytes *rnd = bytes_from_raw(buf, len);
	munit_assert_not_null(rnd);
	free(buf);
	return (rnd);
}


static void
tear_down(void *data)
{
	bytes_free(data);
}


/* The test suite. */
MunitTest test_break_plaintext_suite_tests[] = {
	{ "looks_like_english",          test_looks_like_english,          setup, tear_down, MUNIT_TEST_OPTION_NONE, NULL },
	{ "looks_like_shuffled_english", test_looks_like_shuffled_english, setup, tear_down, MUNIT_TEST_OPTION_NONE, NULL },
	{ "english_char_freq",           test_english_char_freq,           setup, tear_down, MUNIT_TEST_OPTION_NONE, NULL },
	{ "english_word_lengths_freq",   test_english_word_lengths_freq,   setup, tear_down, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mostly_ascii",                test_mostly_ascii,                setup, tear_down, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
