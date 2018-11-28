/*
 * test_bytes.c
 */
#include "munit.h"
#include "helpers.h"
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
	const size_t inlen = strlen(input);

	for (size_t i = 0; i <= inlen; i++) {
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
test_bytes_from_uint32_le(const MunitParameter *params, void *data)
{
	const uint32_t input[] = {
		0x12345678,
		0x00000001,
		0x10000000,
		0xff00ee00,
	};
	const uint8_t expected[] = {
		0x78, 0x56, 0x34,0x12,
		0x01, 0x00, 0x00,0x00,
		0x00, 0x00, 0x00,0x10,
		0x00, 0xee, 0x00,0xff,
	};
	const size_t count = sizeof(input) / sizeof(*input);

	struct bytes *buf = bytes_from_uint32_le(input, count);
	munit_assert_not_null(buf);
	munit_assert_size(buf->len, ==, 4 * count);
	munit_assert_memory_equal(buf->len, buf->data, expected);

	/* when NULL is given */
	munit_assert_null(bytes_from_uint32_le(NULL, 1));

	bytes_free(buf);
	return (MUNIT_OK);
}


static MunitResult
test_bytes_from_uint32_be(const MunitParameter *params, void *data)
{
	const uint32_t input[] = {
		0x12345678,
		0x00000001,
		0x10000000,
		0xff00ee00,
	};
	const uint8_t expected[] = {
		0x12, 0x34, 0x56, 0x78,
		0x00, 0x00, 0x00, 0x01,
		0x10, 0x00, 0x00, 0x00,
		0xff, 0x00, 0xee, 0x00,
	};
	const size_t count = sizeof(input) / sizeof(*input);

	struct bytes *buf = bytes_from_uint32_be(input, count);
	munit_assert_not_null(buf);
	munit_assert_size(buf->len, ==, 4 * count);
	munit_assert_memory_equal(buf->len, buf->data, expected);

	/* when NULL is given */
	munit_assert_null(bytes_from_uint32_be(NULL, 1));

	bytes_free(buf);
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
test_bytes_bcmp(const MunitParameter *params, void *data)
{
	const struct {
		char *a;
		char *b;
		int cmp;
	} vectors[] = {
		{ .a = "",       .b = "",       .cmp = 0 },
		{ .a = "x",      .b = "x",      .cmp = 0 },
		{ .a = "x",      .b = "y",      .cmp = 1 },
		{ .a = "foo",    .b = "bar",    .cmp = 1 },
		{ .a = "foobar", .b = "foobar", .cmp = 0 },
		/* length mismatch */
		{ .a = "x",  .b = "",   .cmp = 1 },
		{ .a = "",   .b = "x",  .cmp = 1 },
		{ .a = "1",  .b = "12", .cmp = 1 },
		{ .a = "12", .b = "1",  .cmp = 1 },
		/* NULL */
		{ .a = NULL,     .b = "foobar", .cmp = 1 },
		{ .a = "foobar", .b = NULL,     .cmp = 1 },
		{ .a = NULL,     .b = NULL,     .cmp = 1 },
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		struct bytes *a = bytes_from_str(vectors[i].a);
		struct bytes *b = bytes_from_str(vectors[i].b);
		int expected = vectors[i].cmp;
		if (vectors[i].a != NULL && a == NULL)
			munit_error("bytes_from_str");
		if (vectors[i].b != NULL && b == NULL)
			munit_error("bytes_from_str");

		munit_assert_int(bytes_bcmp(a, b), ==, expected);

		bytes_free(a);
		bytes_free(b);
	}

	return (MUNIT_OK);
}


static MunitResult
test_bytes_timingsafe_bcmp(const MunitParameter *params, void *data)
{
	const struct {
		char *a;
		char *b;
		int cmp;
	} vectors[] = {
		{ .a = "",       .b = "",       .cmp = 0 },
		{ .a = "x",      .b = "x",      .cmp = 0 },
		{ .a = "x",      .b = "y",      .cmp = 1 },
		{ .a = "foo",    .b = "bar",    .cmp = 1 },
		{ .a = "foobar", .b = "foobar", .cmp = 0 },
		/* length mismatch */
		{ .a = "x",  .b = "",   .cmp = 1 },
		{ .a = "",   .b = "x",  .cmp = 1 },
		{ .a = "1",  .b = "12", .cmp = 1 },
		{ .a = "12", .b = "1",  .cmp = 1 },
		/* NULL */
		{ .a = NULL,     .b = "foobar", .cmp = 1 },
		{ .a = "foobar", .b = NULL,     .cmp = 1 },
		{ .a = NULL,     .b = NULL,     .cmp = 1 },
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		struct bytes *a = bytes_from_str(vectors[i].a);
		struct bytes *b = bytes_from_str(vectors[i].b);
		int expected = vectors[i].cmp;
		if (vectors[i].a != NULL && a == NULL)
			munit_error("bytes_from_str");
		if (vectors[i].b != NULL && b == NULL)
			munit_error("bytes_from_str");

		munit_assert_int(bytes_timingsafe_bcmp(a, b), ==, expected);

		bytes_free(a);
		bytes_free(b);
	}

	return (MUNIT_OK);
}

static MunitResult
test_bytes_find(const MunitParameter *params, void *data)
{
	const struct {
		char *needle;
		char *haystack;
	} vectors[] = {
		{ .needle = "foobar", .haystack = "foobar" },
		{ .needle = "foo",    .haystack = "foobar" },
		{ .needle = "oo",     .haystack = "foobar" },
		{ .needle = "o",      .haystack = "foobar" },
		{ .needle = "bar",    .haystack = "foobar" },
		{ .needle = "r",      .haystack = "foobar" },
		{ .needle = "a",      .haystack = "foobar" },
		{ .needle = "nope",   .haystack = "foobar" },
	};

	size_t index = 0;
	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *needle   = vectors[i].needle;
		const char *haystack = vectors[i].haystack;
		const char *p = strstr(haystack, needle);
		struct bytes *needle_b   = bytes_from_str(needle);
		struct bytes *haystack_b = bytes_from_str(haystack);
		if (needle_b == NULL || haystack_b == NULL)
			munit_error("bytes_from_str");

		const int ret  = bytes_find(haystack_b, needle_b, &index);
		const int nret = bytes_find(haystack_b, needle_b, NULL);
		munit_assert_int(ret, ==, nret);

		if (p == NULL) {
			munit_assert_int(ret, ==, 1);
		} else {
			munit_assert_int(ret, ==, 0);
			const size_t expected = p - haystack;
			munit_assert_int(index, ==, expected);
		}

		bytes_free(haystack_b);
		bytes_free(needle_b);
	}

	/* when NULL is given */
	struct bytes *buf = bytes_from_str("foobar");
	if (buf == NULL)
		munit_error("bytes_from_str");
	munit_assert_int(bytes_find(NULL, buf, NULL),   ==, -1);
	munit_assert_int(bytes_find(NULL, buf, &index), ==, -1);
	munit_assert_int(bytes_find(buf, NULL, NULL),   ==, -1);
	munit_assert_int(bytes_find(buf, NULL, &index), ==, -1);

	/* when an empty buffer is given */
	struct bytes *empty = bytes_from_str("");
	if (empty == NULL)
		munit_error("bytes_from_str");
	munit_assert_int(bytes_find(buf, empty, NULL),   ==, -1);
	munit_assert_int(bytes_find(buf, empty, &index), ==, -1);

	bytes_free(empty);
	bytes_free(buf);
	return (MUNIT_OK);
}


/* Set 2 / Challenge 9 */
static MunitResult
test_bytes_pkcs7_padded(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		uint8_t pad;
		char *expected;
	} vectors[] = {
		{ .input = "",    .pad = 1, .expected = "\x01" },
		{ .input = "",    .pad = 2, .expected = "\x02\x02" },
		{ .input = "foo", .pad = 3, .expected = "foo\x03\x03\x03" },
		{ .input = "foo", .pad = 4, .expected = "foo\x01" },
		{
			.input    = "YELLOW SUBMARINE",
			.pad      = 20,
			.expected = "YELLOW SUBMARINE\x04\x04\x04\x04"
                },
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input    = vectors[i].input;
		const uint8_t pad    = vectors[i].pad;
		const char *expected = vectors[i].expected;
		struct bytes *buf = bytes_from_str(input);
		if (buf == NULL)
			munit_error("bytes_from_str");

		struct bytes *padded = bytes_pkcs7_padded(buf, pad);
		munit_assert_not_null(padded);
		munit_assert_size(padded->len, ==, strlen(expected));
		munit_assert_memory_equal(padded->len, padded->data, expected);

		bytes_free(padded);
		bytes_free(buf);
	}

	/* when NULL is given */
	munit_assert_null(bytes_pkcs7_padded(NULL, 1));

	/* when zero is given */
	struct bytes *buf = bytes_from_str("foobar");
	if (buf == NULL)
		munit_error("bytes_from_str");
	munit_assert_null(bytes_pkcs7_padded(buf, 0));

	bytes_free(buf);
	return (MUNIT_OK);
}


static MunitResult
test_bytes_pkcs7_padding(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		int padded;
		uint8_t expected;
	} vectors[] = {
		{ .input = "ICE ICE BABY\x01",             .padded = 1, .expected = 1 },
		{ .input = "ICE ICE BABY\x02\x02",         .padded = 1, .expected = 2 },
		{ .input = "ICE ICE BABY\x03\x03\x03",     .padded = 1, .expected = 3 },
		{ .input = "ICE ICE BABY\x04\x04\x04\x04", .padded = 1, .expected = 4 },
		{ .input = "ICE ICE BABY\x05\x05\x05\x05", .padded = 0, .expected = 0 },
		{ .input = "ICE ICE BABY\x01\x02\x03\x04", .padded = 0, .expected = 0 },
	};

	uint8_t padding = 0;
	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input      = vectors[i].input;
		const int padded       = vectors[i].padded;
		const uint8_t expected = vectors[i].expected;
		struct bytes *buf = bytes_from_str(input);
		if (buf == NULL)
			munit_error("bytes_from_str");

		const int ret = bytes_pkcs7_padding(buf, &padding);
		if (padded == 0) {
			munit_assert_int(ret, ==, 1);
		} else {
			munit_assert_int(ret, ==, 0);
			munit_assert_uint8(padding, ==, expected);
		}
		munit_assert_int(bytes_pkcs7_padding(buf, NULL), ==, ret);

		bytes_free(buf);
	}

	/* when a buffer with 0x0 at the end is given */
	struct bytes *buf = bytes_from_raw("ICE ICE BABY\x00", 13);
	if (buf == NULL)
		munit_error("bytes_from_raw");
	munit_assert_int(bytes_pkcs7_padding(buf, &padding), ==, 1);
	munit_assert_int(bytes_pkcs7_padding(buf, NULL),     ==, 1);

	/* when NULL is given */
	munit_assert_int(bytes_pkcs7_padding(NULL, &padding), ==, -1);
	munit_assert_int(bytes_pkcs7_padding(NULL, NULL),     ==, -1);

	/* when an empty buffer is given */
	struct bytes *empty = bytes_from_str("");
	if (empty == NULL)
		munit_error("bytes_from_str");
	munit_assert_int(bytes_pkcs7_padding(empty, &padding), ==, -1);
	munit_assert_int(bytes_pkcs7_padding(empty, NULL),     ==, -1);

	bytes_free(empty);
	bytes_free(buf);
	return (MUNIT_OK);
}


/* Set 2 / Challenge 15 */
static MunitResult
test_bytes_pkcs7_unpadded(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		char *expected;
	} vectors[] = {
		{ .input = "ICE ICE BABY\x04\x04\x04\x04", .expected = "ICE ICE BABY" },
		{ .input = "ICE ICE BABY\x05\x05\x05\x05", .expected = NULL },
		{ .input = "ICE ICE BABY\x01\x02\x03\x04", .expected = NULL },
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input    = vectors[i].input;
		const char *expected = vectors[i].expected;
		struct bytes *buf = bytes_from_str(input);
		if (buf == NULL)
			munit_error("bytes_from_str");

		struct bytes *unpadded = bytes_pkcs7_unpadded(buf);
		if (expected == NULL) {
			munit_assert_null(unpadded);
		} else {
			munit_assert_not_null(unpadded);
			munit_assert_size(unpadded->len, ==, strlen(expected));
			munit_assert_memory_equal(unpadded->len, unpadded->data, expected);
		}

		bytes_free(unpadded);
		bytes_free(buf);
	}

	/* when NULL is given */
	munit_assert_null(bytes_pkcs7_unpadded(NULL));

	/* when an empty buffer is given */
	struct bytes *empty = bytes_from_str("");
	if (empty == NULL)
		munit_error("bytes_from_str");
	munit_assert_null(bytes_pkcs7_unpadded(empty));

	/* when the buffer length is to short */
	struct bytes *buf = bytes_from_str("foobar\x08");
	if (buf == NULL)
		munit_error("bytes_from_str");
	munit_assert_null(bytes_pkcs7_unpadded(buf));

	bytes_free(empty);
	bytes_free(buf);
	return (MUNIT_OK);
}


static MunitResult
test_bytes_joined(const MunitParameter *params, void *data)
{
	const struct {
		char *inputs[6];
		size_t count;
		char *expected;
	} vectors[] = {
		{ .inputs = {}, .count = 0, .expected = "" },
		{ .inputs = { "", "" },  .count = 2, .expected = "" },
		{ .inputs = { "", "x" }, .count = 2, .expected = "x" },
		{ .inputs = { "x", "" }, .count = 2, .expected = "x" },
		{ .inputs = { "f", "o", "o" }, .count = 3, .expected = "foo" },
		{ .inputs = { "foo", "ba", "", "r" }, .count = 4, .expected = "foobar" },
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		char *const *inputs = vectors[i].inputs;
		const size_t count   = vectors[i].count;
		const char *expected = vectors[i].expected;

		struct bytes **array = calloc(count, sizeof(struct bytes *));
		if (array == NULL)
			munit_error("calloc");
		for (size_t i = 0; i < count; i++) {
			array[i] = bytes_from_str(inputs[i]);
			if (array[i] == NULL)
				munit_error("bytes_from_str");
		}

		struct bytes *joined = NULL;
		if (count == 0)
			joined = bytes_joined(count);
		else if (count == 1)
			joined = bytes_joined(count, array[0]);
		else if (count == 2)
			joined = bytes_joined(count, array[0], array[1]);
		else if (count == 3)
			joined = bytes_joined(count, array[0], array[1], array[2]);
		else if (count == 4)
			joined = bytes_joined(count, array[0], array[1], array[2], array[3]);
		else
			munit_error("test_bytes_joined with count > 4");

		munit_assert_not_null(joined);
		munit_assert_size(joined->len, ==, strlen(expected));
		munit_assert_memory_equal(joined->len, joined->data, expected);

		for (size_t i = 0; i < count; i++)
			bytes_free(array[i]);
		free(array);
		bytes_free(joined);
	}

	/* when NULL is given */
	munit_assert_null(bytes_joined(1, NULL));

	/* when one of the element is NULL */
	struct bytes *buf = bytes_from_str("foobar");
	if (buf == NULL)
		munit_error("bytes_from_str");
	munit_assert_null(bytes_joined(3, buf, NULL, buf));

	bytes_free(buf);
	return (MUNIT_OK);
}


static MunitResult
test_bytes_put(const MunitParameter *params, void *data)
{
	const struct {
		char *dest;
		size_t offset;
		char *src;
		char *expected;
	} vectors[] = {
		{ .dest = "foo",    .offset = 0, .src = "",    .expected = "foo" },
		{ .dest = "foo",    .offset = 0, .src = "_",   .expected = "_oo" },
		{ .dest = "foo",    .offset = 0, .src = "__",  .expected = "__o" },
		{ .dest = "foo",    .offset = 0, .src = "___", .expected = "___" },
		{ .dest = "foo",    .offset = 1, .src = "__",  .expected = "f__" },
		{ .dest = "foo",    .offset = 3, .src = "",    .expected = "foo" },
		{ .dest = "foobar", .offset = 3, .src = "__",  .expected = "foo__r" },
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		struct bytes *dest   = bytes_from_str(vectors[i].dest);
		const size_t offset  = vectors[i].offset;
		struct bytes *src    = bytes_from_str(vectors[i].src);
		const char *expected = vectors[i].expected;
		if (dest == NULL || src == NULL)
			munit_error("bytes_from_str");

		const int ret = bytes_put(dest, offset, src);
		munit_assert_int(ret, ==, 0);
		munit_assert_size(dest->len, ==, strlen(expected));
		munit_assert_memory_equal(dest->len, dest->data, expected);

		bytes_free(src);
		bytes_free(dest);
	}

	struct bytes *dest = bytes_from_str("foobar");
	struct bytes *src  = bytes_from_str("foobar");
	if (dest == NULL || src == NULL)
		munit_error("bytes_from_str");

	/* when NULL is given */
	munit_assert_int(bytes_put(NULL, 0, dest), ==, -1);
	/* off-by-one offset / src length */
	munit_assert_int(bytes_put(dest, 1, src), ==, -1);
	munit_assert_size(dest->len, ==, strlen("foobar"));
	munit_assert_memory_equal(dest->len, dest->data, "foobar");

	bytes_free(dest);
	bytes_free(src);
	return (MUNIT_OK);
}


static MunitResult
test_bytes_sput(const MunitParameter *params, void *data)
{
	const struct {
		char *dest;
		size_t offset;
		char *src;
		size_t soffset;
		size_t slen;
		char *expected;
	} vectors[] = {
		{ .dest = "foo",    .offset = 0, .src = "",    .soffset = 0, .slen = 0, .expected = "foo" },
		{ .dest = "foo",    .offset = 0, .src = "_",   .soffset = 0, .slen = 1, .expected = "_oo" },
		{ .dest = "foo",    .offset = 0, .src = "__",  .soffset = 0, .slen = 2, .expected = "__o" },
		{ .dest = "foo",    .offset = 0, .src = "___", .soffset = 0, .slen = 3, .expected = "___" },
		{ .dest = "foo",    .offset = 1, .src = "___", .soffset = 1, .slen = 1, .expected = "f_o" },
		{ .dest = "foo",    .offset = 2, .src = "__",  .soffset = 1, .slen = 1, .expected = "fo_" },
		{ .dest = "foo",    .offset = 1, .src = "___", .soffset = 1, .slen = 2, .expected = "f__" },
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		struct bytes *dest   = bytes_from_str(vectors[i].dest);
		const size_t offset  = vectors[i].offset;
		struct bytes *src    = bytes_from_str(vectors[i].src);
		const size_t soffset = vectors[i].soffset;
		const size_t slen    = vectors[i].slen;
		const char *expected = vectors[i].expected;
		if (dest == NULL || src == NULL)
			munit_error("bytes_from_str");

		const int ret = bytes_sput(dest, offset, src, soffset, slen);
		munit_assert_int(ret, ==, 0);
		munit_assert_size(dest->len, ==, strlen(expected));
		munit_assert_memory_equal(dest->len, dest->data, expected);

		bytes_free(src);
		bytes_free(dest);
	}

	struct bytes *dest = bytes_from_str("foobar");
	struct bytes *src  = bytes_from_str("foobar");
	if (dest == NULL || src == NULL)
		munit_error("bytes_from_str");

	/* when NULL is given */
	munit_assert_int(bytes_sput(NULL, 0, dest, 0, dest->len), ==, -1);
	/* off-by-one offset / src length */
	munit_assert_int(bytes_sput(dest, 1, src, 0, dest->len), ==, -1);
	munit_assert_size(dest->len, ==, strlen("foobar"));
	munit_assert_memory_equal(dest->len, dest->data, "foobar");
	/* off-by-one soffset / src length */
	munit_assert_int(bytes_sput(dest, 0, src, 1, dest->len), ==, -1);
	munit_assert_size(dest->len, ==, strlen("foobar"));
	munit_assert_memory_equal(dest->len, dest->data, "foobar");
	/* off-by-one offset / soffset / src length */
	munit_assert_int(bytes_sput(dest, 2, src, 1, dest->len), ==, -1);
	munit_assert_size(dest->len, ==, strlen("foobar"));
	munit_assert_memory_equal(dest->len, dest->data, "foobar");

	bytes_free(dest);
	bytes_free(src);
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
test_bytes_to_uint32_le(const MunitParameter *params, void *data)
{
	const uint8_t input[] = {
		0x78, 0x56, 0x34,0x12,
		0x01, 0x00, 0x00,0x00,
		0x00, 0x00, 0x00,0x10,
		0x00, 0xee, 0x00,0xff,
	};
	const size_t len = sizeof(input) / sizeof(*input);
	const uint32_t expected[] = {
		0x12345678,
		0x00000001,
		0x10000000,
		0xff00ee00,
	};
	const size_t expected_count = sizeof(expected) / sizeof(*expected);

	struct bytes *buf = bytes_from_raw(input, len);
	if (buf == NULL)
		munit_error("bytes_from_raw");

	size_t count = 0;
	uint32_t *words = bytes_to_uint32_le(buf, &count);
	munit_assert_not_null(words);
	munit_assert_size(count, ==, expected_count);
	munit_assert_memory_equal(len, words, expected);
	free(words);
	words = bytes_to_uint32_le(buf, NULL);
	munit_assert_not_null(words);
	munit_assert_memory_equal(len, words, expected);
	free(words);

	/* when NULL is given */
	munit_assert_null(bytes_to_uint32_le(NULL, &count));
	munit_assert_null(bytes_to_uint32_le(NULL, NULL));

	bytes_free(buf);
	return (MUNIT_OK);
}


static MunitResult
test_bytes_to_uint32_be(const MunitParameter *params, void *data)
{
	const uint8_t input[] = {
		0x12, 0x34, 0x56, 0x78,
		0x00, 0x00, 0x00, 0x01,
		0x10, 0x00, 0x00, 0x00,
		0xff, 0x00, 0xee, 0x00,
	};
	const size_t len = sizeof(input) / sizeof(*input);
	const uint32_t expected[] = {
		0x12345678,
		0x00000001,
		0x10000000,
		0xff00ee00,
	};
	const size_t expected_count = sizeof(expected) / sizeof(*expected);

	struct bytes *buf = bytes_from_raw(input, len);
	if (buf == NULL)
		munit_error("bytes_from_raw");

	size_t count = 0;
	uint32_t *words = bytes_to_uint32_be(buf, &count);
	munit_assert_not_null(words);
	munit_assert_size(count, ==, expected_count);
	munit_assert_memory_equal(len, words, expected);
	free(words);
	words = bytes_to_uint32_be(buf, NULL);
	munit_assert_not_null(words);
	munit_assert_memory_equal(len, words, expected);
	free(words);

	/* when NULL is given */
	munit_assert_null(bytes_to_uint32_be(NULL, &count));
	munit_assert_null(bytes_to_uint32_be(NULL, NULL));

	bytes_free(buf);
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


static MunitResult
test_bytes_bzero(const MunitParameter *params, void *data)
{
	const size_t vectors[] = { 0, 1, 2, UINT8_MAX + 1 };

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const size_t len = vectors[i];

		struct bytes *buf = bytes_randomized(len);
		if (buf == NULL)
			munit_error("bytes_randomized");
		bytes_bzero(buf);
		munit_assert_size(buf->len, ==, len);
		for (size_t j = 0; j < len; j++)
			munit_assert_uint8(buf->data[j], ==, 0);

		bytes_free(buf);
	}

	/* should be fine when NULL is given */
	bytes_bzero(NULL);

	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_bytes_suite_tests[] = {
	{ "bytes_zeroed",           test_bytes_zeroed,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_repeated",         test_bytes_repeated,         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_from_raw",         test_bytes_from_raw,         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_from_uint32_le",   test_bytes_from_uint32_le,   NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_from_uint32_be",   test_bytes_from_uint32_be,   NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_from_single",      test_bytes_from_single,      NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_from_str",         test_bytes_from_str,         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_from_hex",         test_bytes_from_hex,         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_from_base64",      test_bytes_from_base64,      NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_dup",              test_bytes_dup,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_bcmp",             test_bytes_bcmp,             NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_timingsafe_bcmp",  test_bytes_timingsafe_bcmp,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_find",             test_bytes_find,             NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_pkcs7_padded",     test_bytes_pkcs7_padded,     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_pkcs7_padding",    test_bytes_pkcs7_padding,    NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_pkcs7_unpadded",   test_bytes_pkcs7_unpadded,   NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_joined",           test_bytes_joined,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_put",              test_bytes_put,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_sput",             test_bytes_sput,             NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_slice",            test_bytes_slice,            NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_slices",           test_bytes_slices,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_hamming_distance", test_bytes_hamming_distance, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_to_uint32_le",     test_bytes_to_uint32_le,     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_to_uint32_be",     test_bytes_to_uint32_be,     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_to_str",           test_bytes_to_str,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_to_hex",           test_bytes_to_hex,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_to_base64",        test_bytes_to_base64,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_hex_to_base64",    test_bytes_hex_to_base64,    NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bytes_bzero",            test_bytes_bzero,            srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
