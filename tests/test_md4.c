/*
 * test_md4.c
 */
#include "munit.h"
#include "md4.h"


static MunitResult
test_md4_hashlength(const MunitParameter *params, void *data)
{
	munit_assert_size(md4_hashlength(), ==, 16);
	return (MUNIT_OK);
}


/* Test Vectors from RFC 1320 APPENDIX A.5 (Test suite) */
static MunitResult
test_md4_hash(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		char *expected; /* in hex */
	} vectors[] = {
		{
			.input    = "",
			.expected = "31D6CFE0D16AE931B73C59D7E0C089C0",
		}, {
			.input    = "a",
			.expected = "BDE52CB31DE33E46245E05FBDBD6FB24",
		}, {
			.input    = "abc",
			.expected = "A448017AAF21D8525FC10AE87AA6729D",
		}, {
			.input    = "message digest",
			.expected = "D9130A8164549FE818874806E1C7014B",
		}, {
			.input    = "abcdefghijklmnopqrstuvwxyz",
			.expected = "D79E1C308AA5BBCDEEA8ED63DF412DA9",
		}, {
			.input    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			.expected = "043F8582F241DB351CE627E153E7F0E4",
		}, {
			.input    = "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
			.expected = "E33B4DDC9C38F2199C3E7B164FCC0536",
		},
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		struct bytes *message = bytes_from_str(vectors[i].input);
		if (message == NULL)
			munit_error("bytes_from_str");
		struct bytes *expected = bytes_from_hex(vectors[i].expected);
		if (expected == NULL)
			munit_error("bytes_from_hex");

		struct bytes *hash = md4_hash(message);
		munit_assert_not_null(hash);
		/* MD4 output is 128-bit */
		munit_assert_size(hash->len, ==, md4_hashlength());
		munit_assert_size(hash->len, ==, expected->len);
		munit_assert_memory_equal(hash->len, hash->data, expected->data);

		bytes_free(hash);
		bytes_free(expected);
		bytes_free(message);
	}

	/* when NULL is given */
	munit_assert_null(md4_hash(NULL));

	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_md4_suite_tests[] = {
	{ "md4_hashlength", test_md4_hashlength, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "md4_hash",       test_md4_hash,       NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
