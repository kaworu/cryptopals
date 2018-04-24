/*
 * main.c
 *
 * Implement the main() function that call munit_suite_main().
 */
#include "munit.h"


/* stuff from other test files */
extern MunitTest test_bytes_suite_tests[];
extern MunitTest test_xor_suite_tests[];
extern MunitTest test_break_plaintext_suite_tests[];
extern MunitTest test_break_single_byte_xor_suite_tests[];
extern MunitTest test_break_repeating_key_xor_suite_tests[];
extern MunitTest test_aes_suite_tests[];
extern MunitTest test_break_ecb_suite_tests[];
extern MunitTest test_uri_suite_tests[];
extern MunitTest test_cookie_suite_tests[];

static MunitSuite all_test_suites[] = {
	{ "bytes/",  test_bytes_suite_tests,                   NULL, 1, MUNIT_SUITE_OPTION_NONE },
	{ "uri/",    test_uri_suite_tests,                     NULL, 1, MUNIT_SUITE_OPTION_NONE },
	{ "cookie/", test_cookie_suite_tests,                  NULL, 1, MUNIT_SUITE_OPTION_NONE },
	{ "xor/",    test_xor_suite_tests,                     NULL, 1, MUNIT_SUITE_OPTION_NONE },
	{ "pt/",     test_break_plaintext_suite_tests,         NULL, 1, MUNIT_SUITE_OPTION_NONE },
	{ "sbx/",    test_break_single_byte_xor_suite_tests,   NULL, 1, MUNIT_SUITE_OPTION_NONE },
	{ "rkx/",    test_break_repeating_key_xor_suite_tests, NULL, 1, MUNIT_SUITE_OPTION_NONE },
	{ "aes/",    test_aes_suite_tests,                     NULL, 1, MUNIT_SUITE_OPTION_NONE },
	{ "ecb/",    test_break_ecb_suite_tests,               NULL, 1, MUNIT_SUITE_OPTION_NONE },
	{
		.prefix     = NULL,
		.tests      = NULL,
		.suites     = NULL,
		.iterations = 0,
		.options    = MUNIT_SUITE_OPTION_NONE
	},
};

/* The main test suite. */
static const MunitSuite test_suite = {
	.prefix     = "",
	.tests      = NULL,
	.suites     = all_test_suites,
	.iterations = 1,
	.options    = MUNIT_SUITE_OPTION_NONE
};


int
main(int argc, char **argv)
{
	/* Finally, we'll actually run our test suite!  That second argument
	 * is the user_data parameter which will be passed either to the
	 * test or (if provided) the fixture setup function. */
	return munit_suite_main(&test_suite, NULL, argc, argv);
}
