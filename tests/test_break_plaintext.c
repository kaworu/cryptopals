/*
 * test_break_plaintext.c
 */
#include "munit.h"
#include "break_plaintext.h"


/* text taken from http://norvig.com/mayzner.html */
static MunitResult
test_looks_like_english(const MunitParameter *params, void *data)
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

	const double prob = looks_like_english(buf);
	munit_assert_double(prob, >, 0.80);

	bytes_free(buf);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_break_plaintext_suite_tests[] = {
	{ "looks_like_english", test_looks_like_english, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
