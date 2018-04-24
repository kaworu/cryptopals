/*
 * test_uri.c
 */
#include <limits.h>

#include "munit.h"
#include "uri.h"


#define	LOWALPHA_CHARS		"abcdefghijklmnopqrstuvwxyz"
#define	UPALPHA_CHARS		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define	DIGITS_CHARS		"0123456789"
#define	MARK_CHARS		"-_.!~*'()"
#define	RESERVED_CHARS		";/?:@&=+$,"
#define	RESERVED_CHARS_ENCODED	"%3B%2F%3F%3A%40%26%3D%2B%24%2C"
#define	OTHER_CHARS		" \"#%<>[\\]^`{|}"
#define	OTHER_CHARS_ENCODED	"%20%22%23%25%3C%3E%5B%5C%5D%5E%60%7B%7C%7D"


static const char *decoded =
	    LOWALPHA_CHARS UPALPHA_CHARS DIGITS_CHARS MARK_CHARS
	    RESERVED_CHARS OTHER_CHARS;

static const char *encoded =
	    LOWALPHA_CHARS UPALPHA_CHARS DIGITS_CHARS MARK_CHARS
	    RESERVED_CHARS_ENCODED OTHER_CHARS_ENCODED;
;


static MunitResult
test_uri_encode_len(const MunitParameter *params, void *data)
{
	int ret = 0;
	size_t len = 0;

	ret = uri_encode_len(decoded, &len);
	munit_assert_int(ret, ==, 0);
	munit_assert_size(len, ==, strlen(encoded));

	/* when NULL is given */
	ret = uri_encode_len(NULL, &len);
	munit_assert_int(ret, ==, -1);
	ret = uri_encode_len(decoded, NULL);
	munit_assert_int(ret, ==, 0);

	return (MUNIT_OK);
}


static MunitResult
test_uri_encode(const MunitParameter *params, void *data)
{
	char *result = NULL;

	result = uri_encode(decoded);
	munit_assert_not_null(result);
	munit_assert_string_equal(result, encoded);

	/* when NULL is given */
	munit_assert_null(uri_encode(NULL));

	free(result);
	return (MUNIT_OK);
}


static MunitResult
test_uri_decode_len(const MunitParameter *params, void *data)
{
	int ret = 0;
	size_t len = 0;

	ret = uri_decode_len(encoded, &len);
	munit_assert_int(ret, ==, 0);
	munit_assert_size(len, ==, strlen(decoded));

	/* when NULL is given */
	ret = uri_decode_len(NULL, &len);
	munit_assert_int(ret, ==, -1);
	ret = uri_decode_len(encoded, NULL);
	munit_assert_int(ret, ==, 0);

	char s[] = "zzz?zzz";
	/* when a decoded string with reserved characters is given */
	for (size_t i = 0; i < strlen(RESERVED_CHARS); i++) {
		s[3] = RESERVED_CHARS[i];
		ret = uri_decode_len(s, NULL);
		munit_assert_int(ret, ==, -1);
	}
	/* when a decoded string with other characters is given */
	for (size_t i = 0; i < strlen(OTHER_CHARS); i++) {
		s[3] = OTHER_CHARS[i];
		ret = uri_decode_len(s, NULL);
		munit_assert_int(ret, ==, -1);
	}

	return (MUNIT_OK);
}


static MunitResult
test_uri_decode(const MunitParameter *params, void *data)
{
	char *result = NULL;

	result = uri_decode(encoded);
	munit_assert_not_null(result);
	munit_assert_string_equal(result, decoded);

	/* when NULL is given */
	munit_assert_null(uri_decode(NULL));

	char s[] = "zzz?zzz";
	/* when a decoded string with reserved characters is given */
	for (size_t i = 0; i < strlen(RESERVED_CHARS); i++) {
		s[3] = RESERVED_CHARS[i];
		munit_assert_null(uri_decode(s));
	}
	/* when a decoded string with other characters is given */
	for (size_t i = 0; i < strlen(OTHER_CHARS); i++) {
		s[3] = OTHER_CHARS[i];
		munit_assert_null(uri_decode(s));
	}

	free(result);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_uri_suite_tests[] = {
	{ "uri_encode_len", test_uri_encode_len, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "uri_encode",     test_uri_encode,     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "uri_decode_len", test_uri_decode_len, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "uri_decode",     test_uri_decode,     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
