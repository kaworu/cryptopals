/*
 * test_uri.c
 */
#include <limits.h>

#include "munit.h"
#include "uri.h"


static const char *unescaped =
	"abcdefghijklmnopqrstuvwxyz" /* lowalpha */
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ" /* upalpha */
	"0123456789"                 /* digit */
	"-_.!~*'()"                  /* mark */
	";/?:@&=+$,"                 /* reserved */
	" \"#%<>[\\]^`{|}"           /* other */
;

static const char *escaped =
	"abcdefghijklmnopqrstuvwxyz"     /* lowalpha */
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"     /* upalpha */
	"0123456789"                     /* digit */
	"-_.!~*'()"                      /* mark */
	"%3B%2F%3F%3A%40%26%3D%2B%24%2C" /* reserved */
	"%20%22%23%25%3C%3E%5B%5C%5D%5E%60%7B%7C%7D" /* other */
;


static MunitResult
test_uri_escape_len(const MunitParameter *params, void *data)
{
	int ret = 0;
	size_t len = 0;

	ret = uri_escape_len(unescaped, &len);
	munit_assert_int(ret, ==, 0);
	munit_assert_size(len, ==, strlen(escaped));

	/* when NULL is given */
	ret = uri_escape_len(NULL, &len);
	munit_assert_int(ret, ==, -1);
	ret = uri_escape_len(unescaped, NULL);
	munit_assert_int(ret, ==, 0);

	return (MUNIT_OK);
}


static MunitResult
test_uri_escape(const MunitParameter *params, void *data)
{
	char *result = NULL;

	result = uri_escape(unescaped);
	munit_assert_not_null(result);
	munit_assert_string_equal(result, escaped);

	/* when NULL is given */
	munit_assert_null(uri_escape(NULL));

	free(result);
	return (MUNIT_OK);
}


static MunitResult
test_uri_unescape_len(const MunitParameter *params, void *data)
{
	int ret = 0;
	size_t len = 0;

	ret = uri_unescape_len(escaped, &len);
	munit_assert_int(ret, ==, 0);
	munit_assert_size(len, ==, strlen(unescaped));

	/* when NULL is given */
	ret = uri_unescape_len(NULL, &len);
	munit_assert_int(ret, ==, -1);
	ret = uri_unescape_len(escaped, NULL);
	munit_assert_int(ret, ==, 0);

	return (MUNIT_OK);
}


static MunitResult
test_uri_unescape(const MunitParameter *params, void *data)
{
	char *result = NULL;

	result = uri_unescape(escaped);
	munit_assert_not_null(result);
	munit_assert_string_equal(result, unescaped);

	/* when NULL is given */
	munit_assert_null(uri_unescape(NULL));

	free(result);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_uri_suite_tests[] = {
	{ "uri_escape_len",   test_uri_escape_len,   NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "uri_escape",       test_uri_escape,       NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "uri_unescape_len", test_uri_unescape_len, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "uri_unescape",     test_uri_unescape,     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
