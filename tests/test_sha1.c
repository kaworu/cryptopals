/*
 * test_sha1.c
 */
#include "munit.h"
#include "sha1.h"


static MunitResult
test_sha1_hashlength(const MunitParameter *params, void *data)
{
	munit_assert_size(sha1_hashlength(), ==, 20);
	return (MUNIT_OK);
}


/* Test Vectors from RFC 3174 */
static MunitResult
test_sha1_hash(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		size_t repeat;
		char *expected; /* in hex */
	} vectors[] = {
		{
			.input    = "abc",
			.repeat   = 1,
			.expected = "A9993E364706816ABA3E25717850C26C9CD0D89D",
		}, {
			.input    = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			.repeat   = 1,
			.expected = "84983E441C3BD26EBAAE4AA1F95129E5E54670F1",
		}, {
			.input    = "a",
			.repeat   = 1000000,
			.expected = "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F",
		}, {
			.input    = "0123456701234567012345670123456701234567012345670123456701234567",
			.repeat   = 10,
			.expected = "DEA356A2CDDD90C7A7ECEDC5EBB563934F460452",
		}
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input = vectors[i].input;
		const size_t ilen = strlen(input);
		const size_t repeat = vectors[i].repeat;
		struct bytes *message = bytes_zeroed(repeat * ilen);
		if (message == NULL)
			munit_error("bytes_zeroed");
		for (size_t i = 0; i < repeat; i++)
			(void)memcpy(message->data + i * ilen, input, ilen);
		struct bytes *expected = bytes_from_hex(vectors[i].expected);
		if (expected == NULL)
			munit_error("bytes_from_hex");

		struct bytes *hash = sha1_hash(message);
		munit_assert_not_null(hash);
		/* SHA-1 output is 160-bit */
		munit_assert_size(hash->len, ==, sha1_hashlength());
		munit_assert_size(hash->len, ==, expected->len);
		munit_assert_memory_equal(hash->len, hash->data, expected->data);

		bytes_free(hash);
		bytes_free(expected);
		bytes_free(message);
	}

	/* when NULL is given */
	munit_assert_null(sha1_hash(NULL));

	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_sha1_suite_tests[] = {
	{ "sha1_hashlength", test_sha1_hashlength, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "sha1_hash",       test_sha1_hash,       NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
