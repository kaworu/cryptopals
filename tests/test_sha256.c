/*
 * test_sha256.c
 */
#include "munit.h"
#include "sha256.h"


static MunitResult
test_sha256_hashlength(const MunitParameter *params, void *data)
{
	munit_assert_size(sha256_hashlength(), ==, 32);
	return (MUNIT_OK);
}


static MunitResult
test_sha256_blocksize(const MunitParameter *params, void *data)
{
	munit_assert_size(sha256_blocksize(), ==, 64);
	return (MUNIT_OK);
}


/* Test Vectors from RFC 6234 (§ 8.5) */
static MunitResult
test_sha256_hash(const MunitParameter *params, void *data)
{
	/*
	 * NOTE: We don't support the "extra bits" feature. Thus, the numbering
	 * reflect the test number from the RFC and the test cases 5, 7, and 9
	 * are missing.
	 */
	const struct {
		char *input;
		size_t inputlen;
		size_t repeat;
		char *expected; /* in hex */
	} vectors[] = {
		{ /* 1 */
			.input    = "abc",
			.inputlen = 3,
			.repeat   = 1,
			.expected = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
		}, { /* 2 */
			.input    = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			.inputlen = 56,
			.repeat   = 1,
			.expected = "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1",
		}, { /* 3 */
			.input    = "a",
			.inputlen = 1,
			.repeat   = 1000000,
			.expected = "CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0",
		}, { /* 4 */
			.input    = "0123456701234567012345670123456701234567012345670123456701234567",
			.inputlen = 64,
			.repeat   = 10,
			.expected = "594847328451BDFA85056225462CC1D867D877FB388DF0CE35F25AB5562BFBB5",
		}, { /* 6 */
			.input    = "\x19",
			.inputlen = 1,
			.repeat   = 1,
			.expected = "68AA2E2EE5DFF96E3355E6C7EE373E3D6A4E17F75F9518D843709C0C9BC3E3D4",
		}, { /* 8 */
			.input    = "\xe3\xd7\x25\x70\xdc\xdd\x78\x7c\xe3\x88\x7a\xb2\xcd\x68\x46\x52",
			.inputlen = 64 / 4,
			.repeat   = 1,
			.expected = "175EE69B02BA9B58E2B0A5FD13819CEA573F3940A94F825128CF4209BEABB4E8",
		}, { /* 10 */
			.input    = "\x83\x26\x75\x4e\x22\x77\x37\x2f\x4f\xc1\x2b\x20\x52\x7a\xfe\xf0"
				    "\x4d\x8a\x05\x69\x71\xb1\x1a\xd5\x71\x23\xa7\xc1\x37\x76\x00\x00"
				    "\xd7\xbe\xf6\xf3\xc1\xf7\xa9\x08\x3a\xa3\x9d\x81\x0d\xb3\x10\x77"
				    "\x7d\xab\x8b\x1e\x7f\x02\xb8\x4a\x26\xc7\x73\x32\x5f\x8b\x23\x74"
				    "\xde\x7a\x4b\x5a\x58\xcb\x5c\x5c\xf3\x5b\xce\xe6\xfb\x94\x6e\x5b"
				    "\xd6\x94\xfa\x59\x3a\x8b\xeb\x3f\x9d\x65\x92\xec\xed\xaa\x66\xca"
				    "\x82\xa2\x9d\x0c\x51\xbc\xf9\x33\x62\x30\xe5\xd7\x84\xe4\xc0\xa4"
				    "\x3f\x8d\x79\xa3\x0a\x16\x5c\xba\xbe\x45\x2b\x77\x4b\x9c\x71\x09"
				    "\xa9\x7d\x13\x8f\x12\x92\x28\x96\x6f\x6c\x0a\xdc\x10\x6a\xad\x5a"
				    "\x9f\xdd\x30\x82\x57\x69\xb2\xc6\x71\xaf\x67\x59\xdf\x28\xeb\x39"
				    "\x3d\x54\xd6",
			.inputlen = (10 * 64 + 12) / 4,
			.repeat   = 1,
			.expected = "97DBCA7DF46D62C8A422C941DD7E835B8AD3361763F7E9B2D95F4F0DA6E1CCBC",
		},
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input = vectors[i].input;
		const size_t ilen = vectors[i].inputlen;
		const size_t repeat = vectors[i].repeat;
		struct bytes *message = bytes_zeroed(repeat * ilen);
		if (message == NULL)
			munit_error("bytes_zeroed");
		for (size_t i = 0; i < repeat; i++)
			(void)memcpy(message->data + i * ilen, input, ilen);
		struct bytes *expected = bytes_from_hex(vectors[i].expected);
		if (expected == NULL)
			munit_error("bytes_from_hex");

		struct bytes *hash = sha256_hash(message);
		munit_assert_not_null(hash);
		/* SHA-256 output is 256-bit */
		munit_assert_size(hash->len, ==, sha256_hashlength());
		munit_assert_size(hash->len, ==, expected->len);
		munit_assert_memory_equal(hash->len, hash->data, expected->data);

		bytes_free(hash);
		bytes_free(expected);
		bytes_free(message);
	}

	/* when NULL is given */
	munit_assert_null(sha256_hash(NULL));

	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_sha256_suite_tests[] = {
	{ "sha256_hashlength", test_sha256_hashlength, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "sha256_blocksize",  test_sha256_blocksize,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "sha256_hash",       test_sha256_hash,       NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
