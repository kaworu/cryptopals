/*
 * test_bytes.c
 */
#include <stdlib.h>

#include "munit.h"
#include "bytes.h"


static MunitResult
test_bytes_from_str(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		size_t expected;
	} vectors[] = {
		{ .input = "",       .expected = 0 },
		{ .input = "f",      .expected = 1 },
		{ .input = "fo",     .expected = 2 },
		{ .input = "foo",    .expected = 3 },
		{ .input = "foob",   .expected = 4 },
		{ .input = "fooba",  .expected = 5 },
		{ .input = "foobar", .expected = 6 },
	};

	for (int i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input = vectors[i].input;
		const size_t expected = vectors[i].expected;

		struct bytes *buf = bytes_from_str(input);
		if (buf == NULL)
			return (MUNIT_ERROR);

		munit_assert_size(buf->len, ==, expected);
		munit_assert_memory_equal(buf->len, buf->data, input);

		free(buf);
	}

	/* when NULL is given */
	munit_assert_null(bytes_from_str(NULL));

	return (MUNIT_OK);
}


/* Test Vectors from RFC 4648 */
static MunitResult
test_bytes_from_hex(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		char *expected;
	} vectors[] = {
		{ .input = "",             .expected = "" },
		{ .input = "66",           .expected = "f" },
		{ .input = "666F",         .expected = "fo" },
		{ .input = "666F6F",       .expected = "foo" },
		{ .input = "666F6F62",     .expected = "foob" },
		{ .input = "666F6F6261",   .expected = "fooba" },
		{ .input = "666F6F626172", .expected = "foobar" },
		/* Added this one for case-insensitiveness compliance. */
		{ .input = "666f6f626172", .expected = "foobar" },
	};

	for (int i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input = vectors[i].input;
		const char *expected = vectors[i].expected;

		struct bytes *buf = bytes_from_hex(input);
		if (buf == NULL)
			return (MUNIT_ERROR);

		munit_assert_size(buf->len, ==, strlen(expected));
		munit_assert_memory_equal(buf->len, buf->data, expected);

		free(buf);
	}

	/* when NULL is given */
	munit_assert_null(bytes_from_hex(NULL));

	/* test with a string not hex-encoded */
	munit_assert_null(bytes_from_hex("!0x"));

	return (MUNIT_OK);
}


static MunitResult
test_bytes_copy(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
	} vectors[] = {
		{ .input = "" },
		{ .input = "f" },
		{ .input = "fo" },
		{ .input = "foo" },
		{ .input = "foob" },
		{ .input = "fooba" },
		{ .input = "foobar" },
	};

	for (int i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input = vectors[i].input;

		struct bytes *buf = bytes_from_str(input);
		if (buf == NULL)
			return (MUNIT_ERROR);

		struct bytes *cpy = bytes_copy(buf);
		if (cpy == NULL)
			return (MUNIT_ERROR);

		munit_assert_size(buf->len, ==, cpy->len);
		munit_assert_memory_equal(buf->len, buf->data, cpy->data);

		free(cpy);
		free(buf);
	}

	/* when NULL is given */
	munit_assert_null(bytes_copy(NULL));

	return (MUNIT_OK);
}


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


static MunitResult
test_bytes_to_hex(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		char *expected;
	} vectors[] = {
		{ .input = "",       .expected = "" },
		{ .input = "f",      .expected = "66" },
		{ .input = "fo",     .expected = "666F" },
		{ .input = "foo",    .expected = "666F6F" },
		{ .input = "foob",   .expected = "666F6F62" },
		{ .input = "fooba",  .expected = "666F6F6261" },
		{ .input = "foobar", .expected = "666F6F626172" },
	};

	for (int i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input = vectors[i].input;
		const char *expected = vectors[i].expected;

		struct bytes *buf = bytes_from_str(input);
		if (buf == NULL)
			return (MUNIT_ERROR);

		char *result = bytes_to_hex(buf);
		if (result == NULL)
			return (MUNIT_ERROR);

		munit_assert_string_equal(result, expected);

		free(result);
		free(buf);
	}

	/* when NULL is given */
	munit_assert_null(bytes_to_hex(NULL));

	return (MUNIT_OK);
}


static MunitResult
test_bytes_to_str(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		char *expected;
	} vectors[] = {
		{ .input = "",       .expected = "" },
		{ .input = "f",      .expected = "f" },
		{ .input = "fo",     .expected = "fo" },
		{ .input = "foo",    .expected = "foo" },
		{ .input = "foob",   .expected = "foob" },
		{ .input = "fooba",  .expected = "fooba" },
		{ .input = "foobar", .expected = "foobar" },
	};

	for (int i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input = vectors[i].input;
		const char *expected = vectors[i].expected;

		struct bytes *buf = bytes_from_str(input);
		if (buf == NULL)
			return (MUNIT_ERROR);

		char *result = bytes_to_str(buf);
		if (result == NULL)
			return (MUNIT_ERROR);

		munit_assert_string_equal(result, expected);

		free(result);
		free(buf);
	}

	/* when NULL is given */
	munit_assert_null(bytes_to_str(NULL));

	return (MUNIT_OK);
}


/* Test Vectors from RFC 4648 */
static MunitResult
test_bytes_to_base64(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		char *expected;
	} vectors[] = {
		{ .input = "",       .expected = "" },
		{ .input = "f",      .expected = "Zg==" },
		{ .input = "fo",     .expected = "Zm8=" },
		{ .input = "foo",    .expected = "Zm9v" },
		{ .input = "foob",   .expected = "Zm9vYg==" },
		{ .input = "fooba",  .expected = "Zm9vYmE=" },
		{ .input = "foobar", .expected = "Zm9vYmFy" },
	};

	for (int i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input = vectors[i].input;
		const char *expected = vectors[i].expected;

		struct bytes *buf = bytes_from_str(input);
		if (buf == NULL)
			return (MUNIT_ERROR);

		char *result = bytes_to_base64(buf);
		if (result == NULL)
			return (MUNIT_ERROR);

		munit_assert_string_equal(result, expected);

		free(result);
		free(buf);
	}

	/* when NULL is given */
	munit_assert_null(bytes_to_base64(NULL));

	return (MUNIT_OK);
}


/* Set 1 / Challenge 1 */
static MunitResult
test_bytes_hex_to_base64(const MunitParameter *params, void *data)
{
	const char *hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	const char *expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

	struct bytes *buf = bytes_from_hex(hex);
	if (buf == NULL)
		return (MUNIT_ERROR);

	char *result = bytes_to_base64(buf);
	if (result == NULL)
		return (MUNIT_ERROR);

	munit_assert_string_equal(result, expected);

	free(result);
	free(buf);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_bytes_suite_tests[] = {
	{ "bytes_from_str",      test_bytes_from_str,      NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_from_hex",      test_bytes_from_hex,      NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_copy",          test_bytes_copy,          NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_xor",           test_bytes_xor,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_to_str",        test_bytes_to_str,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_to_hex",        test_bytes_to_hex,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_to_base64",     test_bytes_to_base64,     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_hex_to_base64", test_bytes_hex_to_base64, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
