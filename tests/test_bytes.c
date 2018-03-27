/*
 * test_bytes.c
 */
#include "munit.h"
#include "bytes.h"


static MunitResult
test_bytes_zeroed(const MunitParameter *params, void *data)
{
	const size_t vectors[] = { 0, 1, 2, UINT8_MAX + 1 };

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const size_t len = vectors[i];

		struct bytes *buf = bytes_zeroed(len);
		munit_assert_not_null(buf);
		munit_assert_size(buf->len, ==, len);
		for (size_t j = 0; j < len; j++)
			munit_assert_uint8(buf->data[j], ==, 0);

		bytes_free(buf);
	}

	return (MUNIT_OK);
}


static MunitResult
test_bytes_repeated(const MunitParameter *params, void *data)
{
	const uint8_t vectors[] = { 0, 1, 2, UINT8_MAX };

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const uint8_t n = vectors[i];

		struct bytes *buf = bytes_repeated(n, n);
		munit_assert_not_null(buf);
		munit_assert_size(buf->len, ==, n);
		for (size_t j = 0; j < n; j++)
			munit_assert_uint8(buf->data[j], ==, n);

		bytes_free(buf);
	}

	return (MUNIT_OK);
}


static MunitResult
test_bytes_from_raw(const MunitParameter *params, void *data)
{
	const char *input = "foobar";

	for (size_t i = 0; i <= sizeof(input); i++) {
		struct bytes *buf = bytes_from_raw(input, i);
		munit_assert_not_null(buf);
		munit_assert_size(buf->len, ==, i);
		munit_assert_memory_equal(buf->len, buf->data, input);

		bytes_free(buf);
	}

	/* when NULL is given */
	munit_assert_null(bytes_from_raw(NULL, 1));

	return (MUNIT_OK);
}


static MunitResult
test_bytes_from_single(const MunitParameter *params, void *data)
{
	const uint8_t vectors[] = {
		0x0, 0x1, 0xa0, 0xef, 0xfe, 0xff
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const uint8_t byte = vectors[i];

		struct bytes *buf = bytes_from_single(byte);
		munit_assert_not_null(buf);
		munit_assert_size(buf->len, ==, 1);
		munit_assert_memory_equal(1, buf->data, &byte);

		bytes_free(buf);
	}

	return (MUNIT_OK);
}


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

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input = vectors[i].input;
		const size_t expected = vectors[i].expected;

		struct bytes *buf = bytes_from_str(input);
		munit_assert_not_null(buf);
		munit_assert_size(buf->len, ==, expected);
		munit_assert_memory_equal(buf->len, buf->data, input);

		bytes_free(buf);
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

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input = vectors[i].input;
		const char *expected = vectors[i].expected;

		struct bytes *buf = bytes_from_hex(input);
		munit_assert_not_null(buf);
		munit_assert_size(buf->len, ==, strlen(expected));
		munit_assert_memory_equal(buf->len, buf->data, expected);

		bytes_free(buf);
	}

	/* when NULL is given */
	munit_assert_null(bytes_from_hex(NULL));
	/* when the input string is not hex-encoded */
	munit_assert_null(bytes_from_hex("!0x"));

	return (MUNIT_OK);
}


/* Test Vectors from RFC 4648 */
static MunitResult
test_bytes_from_base64(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		char *expected;
	} vectors[] = {
		{ .input = "",         .expected = "" },
		{ .input = "Zg==",     .expected = "f" },
		{ .input = "Zm8=",     .expected = "fo" },
		{ .input = "Zm9v",     .expected = "foo" },
		{ .input = "Zm9vYg==", .expected = "foob" },
		{ .input = "Zm9vYmE=", .expected = "fooba" },
		{ .input = "Zm9vYmFy", .expected = "foobar" },
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input = vectors[i].input;
		const char *expected = vectors[i].expected;

		struct bytes *buf = bytes_from_base64(input);
		munit_assert_not_null(buf);
		munit_assert_size(buf->len, ==, strlen(expected));
		munit_assert_memory_equal(buf->len, buf->data, expected);

		bytes_free(buf);
	}

	/* when NULL is given */
	munit_assert_null(bytes_from_base64(NULL));
	/* when the input string is not base64-encoded */
	munit_assert_null(bytes_from_base64("!base64"));

	return (MUNIT_OK);
}


static MunitResult
test_bytes_dup(const MunitParameter *params, void *data)
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

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input = vectors[i].input;
		struct bytes *buf = bytes_from_str(input);
		if (buf == NULL)
			munit_error("bytes_from_str");

		struct bytes *cpy = bytes_dup(buf);
		munit_assert_not_null(cpy);
		munit_assert_size(buf->len, ==, cpy->len);
		munit_assert_memory_equal(buf->len, buf->data, cpy->data);

		bytes_free(cpy);
		bytes_free(buf);
	}

	/* when NULL is given */
	munit_assert_null(bytes_dup(NULL));

	return (MUNIT_OK);
}


static MunitResult
test_bytes_slice(const MunitParameter *params, void *data)
{
	struct bytes *buf = bytes_from_str("foobar");
	if (buf == NULL)
		munit_error("bytes_from_str");

	for (size_t offset = 0; offset <= buf->len; offset++) {
		const size_t maxlen = buf->len - offset;
		for (size_t len = 0; len <= maxlen; len++) {
			struct bytes *slice = bytes_slice(buf, offset, len);
			munit_assert_not_null(slice);
			munit_assert_size(slice->len, ==, len);
			munit_assert_memory_equal(slice->len,
			    buf->data + offset, slice->data);
			bytes_free(slice);
		}
	}

	/* when NULL is given */
	munit_assert_null(bytes_slice(NULL, 0, 0));
	/* invalid offset */
	munit_assert_null(bytes_slice(buf, buf->len + 1, 0));
	/* invalid length */
	munit_assert_null(bytes_slice(buf, 1, buf->len));

	bytes_free(buf);
	return (MUNIT_OK);
}


static MunitResult
test_bytes_slices(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		size_t offset;
		size_t size;
		size_t jump;
		char *expected;
	} vectors[] = {
		/*
		 * jump=0, testing only offset and size
		 */
		{ .input = "12345j", .offset = 0, .size = 6, .jump = 0, .expected = "12345j" },
		{ .input = "12345j", .offset = 1, .size = 5, .jump = 0, .expected = "2345j" },
		{ .input = "12345j", .offset = 5, .size = 1, .jump = 0, .expected = "j" },
		{ .input = "12345j", .offset = 0, .size = 1, .jump = 0, .expected = "12345j" },
		/* incomplete first slice */
		{ .input = "12345j", .offset = 0, .size = 7, .jump = 0, .expected = "12345j" },
		/* imcomplete last slice */
		{ .input = "12345j", .offset = 0, .size = 4, .jump = 0, .expected = "12345j" },
		/*
		 * offset=0, testing only size and jump
		 */
		{ .input = "o23456", .offset = 0, .size = 1, .jump = 1, .expected = "o35" },
		{ .input = "o23456", .offset = 0, .size = 2, .jump = 1, .expected = "o245" },
		{ .input = "o23456", .offset = 0, .size = 1, .jump = 2, .expected = "o4" },
		{ .input = "o23456", .offset = 0, .size = 1, .jump = 3, .expected = "o5" },
		{ .input = "o23456", .offset = 0, .size = 1, .jump = 4, .expected = "o6" },
		{ .input = "o23456", .offset = 0, .size = 1, .jump = 5, .expected = "o" },
		/* jump outside */
		{ .input = "o23456", .offset = 0, .size = 1, .jump = 6, .expected = "o" },
		/* imcomplete first slice */
		{ .input = "o23456", .offset = 0, .size = 7, .jump = 1, .expected = "o23456" },
		/* imcomplete last slice */
		{ .input = "o23456", .offset = 0, .size = 2, .jump = 3, .expected = "o26" },
		/*
		 * all parameters > 0
		 */
		{ .input = "12345a", .offset = 1, .size = 1, .jump = 1, .expected = "24a" },
		{ .input = "12345a", .offset = 2, .size = 2, .jump = 1, .expected = "34a" },
		/* jump outside */
		{ .input = "12345a", .offset = 5, .size = 1, .jump = 5, .expected = "a" },
		/* imcomplete first slice */
		{ .input = "12345a", .offset = 2, .size = 5, .jump = 9, .expected = "345a" },
		/* imcomplete last slice */
		{ .input = "12345a", .offset = 1, .size = 2, .jump = 2, .expected = "23a" },
		/* from the documentation example */
		{ .input = "123456e", .offset = 1, .size = 2, .jump = 3, .expected = "23e" },
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input    = vectors[i].input;
		const size_t offset  = vectors[i].offset;
		const size_t size    = vectors[i].size;
		const size_t jump    = vectors[i].jump;
		const char *expected = vectors[i].expected;

		struct bytes *buf = bytes_from_str(input);
		if (buf == NULL)
			munit_error("bytes_from_str");
		struct bytes *result = bytes_slices(buf, offset, size, jump);
		munit_assert_not_null(result);
		munit_assert_size(result->len, ==, strlen(expected));
		munit_assert_memory_equal(result->len, result->data, expected);

		bytes_free(result);
		bytes_free(buf);
	}

	struct bytes *buf = bytes_from_str("foobar");
	if (buf == NULL)
		munit_error("bytes_from_str");
	/* when NULL is given */
	munit_assert_null(bytes_slices(NULL, 1, 1, 1));
	/* invalid offset */
	munit_assert_null(bytes_slices(buf, buf->len + 1, 1, 1));
	/* invalid size */
	munit_assert_null(bytes_slices(buf, 1, 0, 1));
	/* no data */
	munit_assert_null(bytes_slices(buf, buf->len, 1, 0));

	bytes_free(buf);
	return (MUNIT_OK);
}


/* first part of Set 1 / Challenge 6 */
static MunitResult
test_bytes_hamming_distance(const MunitParameter *params, void *data)
{
	struct bytes *a = bytes_from_str("this is a test");
	struct bytes *b = bytes_from_str("wokka wokka!!!");
	if (a == NULL || b == NULL)
		munit_error("bytes_from_str");

	intmax_t retval = bytes_hamming_distance(a, b);
	munit_assert_int64((int64_t)retval, ==, 37);

	bytes_free(b);
	bytes_free(a);
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

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input = vectors[i].input;
		const char *expected = vectors[i].expected;
		struct bytes *buf = bytes_from_str(input);
		if (buf == NULL)
			munit_error("bytes_from_str");

		char *result = bytes_to_str(buf);
		munit_assert_not_null(result);
		munit_assert_string_equal(result, expected);

		free(result);
		bytes_free(buf);
	}

	/* when NULL is given */
	munit_assert_null(bytes_to_str(NULL));

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

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input = vectors[i].input;
		const char *expected = vectors[i].expected;
		struct bytes *buf = bytes_from_str(input);
		if (buf == NULL)
			munit_error("bytes_from_str");

		char *result = bytes_to_hex(buf);
		munit_assert_not_null(result);
		munit_assert_string_equal(result, expected);

		free(result);
		bytes_free(buf);
	}

	/* when NULL is given */
	munit_assert_null(bytes_to_hex(NULL));

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

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input = vectors[i].input;
		const char *expected = vectors[i].expected;
		struct bytes *buf = bytes_from_str(input);
		if (buf == NULL)
			munit_error("bytes_from_str");

		char *result = bytes_to_base64(buf);
		munit_assert_not_null(result);
		munit_assert_string_equal(result, expected);

		free(result);
		bytes_free(buf);
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
	char *result = bytes_to_base64(buf);
	munit_assert_not_null(buf);
	munit_assert_not_null(result);
	munit_assert_string_equal(result, expected);

	free(result);
	bytes_free(buf);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_bytes_suite_tests[] = {
	{ "bytes_zeroed",           test_bytes_zeroed,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_repeated",         test_bytes_repeated,         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_from_raw",         test_bytes_from_raw,         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_from_single",      test_bytes_from_single,      NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_from_str",         test_bytes_from_str,         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_from_hex",         test_bytes_from_hex,         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_from_base64",      test_bytes_from_base64,      NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_dup",              test_bytes_dup,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_slice",            test_bytes_slice,            NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_slices",           test_bytes_slices,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_hamming_distance", test_bytes_hamming_distance, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_to_str",           test_bytes_to_str,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_to_hex",           test_bytes_to_hex,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_to_base64",        test_bytes_to_base64,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_hex_to_base64",    test_bytes_hex_to_base64,    NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
