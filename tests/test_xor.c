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

	struct bytes *buf = bytes_from_hex(lhs);
	if (buf == NULL)
		return (MUNIT_ERROR);

	struct bytes *mask = bytes_from_hex(rhs);
	if (buf == NULL)
		return (MUNIT_ERROR);

	int retval = bytes_xor(buf, mask);
	munit_assert_int(retval, ==, 0);

	char *result = bytes_to_hex(buf);
	if (result == NULL)
		return (MUNIT_ERROR);

	munit_assert_string_equal(result, expected);

	struct bytes *empty = bytes_from_str("");
	if (empty == NULL)
		return (MUNIT_ERROR);

	struct bytes *cpy = bytes_copy(buf);
	if (cpy == NULL)
		return (MUNIT_ERROR);

	/* when NULL is given */
	munit_assert_int(bytes_xor(NULL, mask), ==, -1);
	munit_assert_int(bytes_xor(buf,  NULL), ==, -1);
	munit_assert_int(bytes_xor(NULL, NULL), ==, -1);
	/* check that buf has not be modified */
	munit_assert_size(buf->len, ==, cpy->len);
	munit_assert_memory_equal(buf->len, buf->data, cpy->data);

	/* when the length doesn't match */
	munit_assert_int(bytes_xor(buf, empty), ==, -1);
	/* check that buf has not be modified */
	munit_assert_size(buf->len, ==, cpy->len);
	munit_assert_memory_equal(buf->len, buf->data, cpy->data);

	free(cpy);
	free(empty);
	free(result);
	free(mask);
	free(buf);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_xor_suite_tests[] = {
	{ "bytes_xor", test_bytes_xor, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
