/*
 * test_mac.c
 */
#include "munit.h"
#include "sha1.h"
#include "md4.h"
#include "sha256.h"
#include "mac.h"


/* Set 4 / Challenge 28 */
static MunitResult
test_sha1_mac_keyed_prefix(const MunitParameter *params, void *data)
{
	/* NOTE: reusing some vectors from test_sha1_hash() */
	const struct {
		char *key;
		char *message;
		char *expected; /* in hex */
	} vectors[] = {
		{
			.key      = "a",
			.message  = "bc",
			.expected = "A9993E364706816ABA3E25717850C26C9CD0D89D",
		}, {
			.key      = "abcdbcdecde",
			.message  = "fdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			.expected = "84983E441C3BD26EBAAE4AA1F95129E5E54670F1",
		}
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		struct bytes *key = bytes_from_str(vectors[i].key);
		if (key == NULL)
			munit_error("bytes_from_str");
		struct bytes *message = bytes_from_str(vectors[i].message);
		if (message == NULL)
			munit_error("bytes_from_str");
		struct bytes *expected = bytes_from_hex(vectors[i].expected);
		if (expected == NULL)
			munit_error("bytes_from_hex");

		struct bytes *mac = sha1_mac_keyed_prefix(key, message);
		munit_assert_not_null(mac);
		/* SHA-1 output is 160-bit */
		munit_assert_size(mac->len, ==, sha1_hashlength());
		munit_assert_size(mac->len, ==, expected->len);
		munit_assert_memory_equal(mac->len, mac->data, expected->data);

		bytes_free(mac);
		bytes_free(expected);
		bytes_free(message);
		bytes_free(key);
	}

	/* when NULL is given */
	struct bytes *empty = bytes_from_str("");
	if (empty == NULL)
		munit_error("bytes_from_str");
	munit_assert_null(sha1_mac_keyed_prefix(NULL,  empty));
	munit_assert_null(sha1_mac_keyed_prefix(empty, NULL));
	munit_assert_null(sha1_mac_keyed_prefix(NULL,  NULL));

	bytes_free(empty);
	return (MUNIT_OK);
}


/* Set 4 / Challenge 28 */
static MunitResult
test_sha1_mac_keyed_prefix_verify(const MunitParameter *params, void *data)
{
	struct bytes *key = bytes_from_str("YELLOW SUBMARINE");
	struct bytes *msg = bytes_from_str("rendez-vous at 6am");
	struct bytes *msg_tempered = bytes_from_str("rendez-vous at 6pm");
	if (key == NULL || msg == NULL || msg_tempered == NULL)
		munit_error("bytes_from_str");
	struct bytes *mac = sha1_mac_keyed_prefix(key, msg);
	if (mac == NULL)
		munit_error("sha1_mac_keyed_prefix");

	/* verify the message against its MAC */
	int ret = sha1_mac_keyed_prefix_verify(key, msg, mac);
	munit_assert_int(ret, ==, 0);

	/* verify a tempered version of the message against the MAC */
	ret = sha1_mac_keyed_prefix_verify(key, msg_tempered, mac);
	munit_assert_int(ret, ==, 1);

	/* attempt to MAC without knowing the key */
	struct bytes *hash = sha1_hash(msg);
	if (hash == NULL)
		munit_error("sha1_hash");
	ret = sha1_mac_keyed_prefix_verify(key, msg, hash);
	munit_assert_int(ret, ==, 1);

	/* when NULL is given */
	ret = sha1_mac_keyed_prefix_verify(NULL, msg,  mac);
	munit_assert_int(ret, ==, -1);
	ret = sha1_mac_keyed_prefix_verify(key,  NULL, mac);
	munit_assert_int(ret, ==, -1);
	ret = sha1_mac_keyed_prefix_verify(key,  msg,  NULL);
	munit_assert_int(ret, ==, -1);

	bytes_free(hash);
	bytes_free(mac);
	bytes_free(msg_tempered);
	bytes_free(msg);
	bytes_free(key);
	return (MUNIT_OK);
}


/* Set 4 / Challenge 30 */
static MunitResult
test_md4_mac_keyed_prefix(const MunitParameter *params, void *data)
{
	/* NOTE: reusing some vectors from test_md4_hash() */
	const struct {
		char *key;
		char *message;
		char *expected; /* in hex */
	} vectors[] = {
		{
			.key      = "",
			.message  = "",
			.expected = "31D6CFE0D16AE931B73C59D7E0C089C0",
		}, {
			.key      = "",
			.message  = "a",
			.expected = "BDE52CB31DE33E46245E05FBDBD6FB24",
		}, {
			.key      = "a",
			.message  = "bc",
			.expected = "A448017AAF21D8525FC10AE87AA6729D",
		}, {
			.key      = "message",
			.message  = " digest",
			.expected = "D9130A8164549FE818874806E1C7014B",
		}, {
			.key      = "abcdefghijk",
			.message  = "lmnopqrstuvwxyz",
			.expected = "D79E1C308AA5BBCDEEA8ED63DF412DA9",
		}, {
			.key      = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			.message  = "abcdefghijklmnopqrstuvwxyz0123456789",
			.expected = "043F8582F241DB351CE627E153E7F0E4",
		}, {
			.key      = "1234567890123456789012345678901234567890123456789012345678901",
			.message  = "2345678901234567890",
			.expected = "E33B4DDC9C38F2199C3E7B164FCC0536",
		},
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		struct bytes *key = bytes_from_str(vectors[i].key);
		if (key == NULL)
			munit_error("bytes_from_str");
		struct bytes *message = bytes_from_str(vectors[i].message);
		if (message == NULL)
			munit_error("bytes_from_str");
		struct bytes *expected = bytes_from_hex(vectors[i].expected);
		if (expected == NULL)
			munit_error("bytes_from_hex");

		struct bytes *mac = md4_mac_keyed_prefix(key, message);
		munit_assert_not_null(mac);
		/* MD4 output is 128-bit */
		munit_assert_size(mac->len, ==, md4_hashlength());
		munit_assert_size(mac->len, ==, expected->len);
		munit_assert_memory_equal(mac->len, mac->data, expected->data);

		bytes_free(mac);
		bytes_free(expected);
		bytes_free(message);
		bytes_free(key);
	}

	/* when NULL is given */
	struct bytes *empty = bytes_from_str("");
	if (empty == NULL)
		munit_error("bytes_from_str");
	munit_assert_null(md4_mac_keyed_prefix(NULL,  empty));
	munit_assert_null(md4_mac_keyed_prefix(empty, NULL));
	munit_assert_null(md4_mac_keyed_prefix(NULL,  NULL));

	bytes_free(empty);
	return (MUNIT_OK);
}


/* Set 4 / Challenge 30 */
static MunitResult
test_md4_mac_keyed_prefix_verify(const MunitParameter *params, void *data)
{
	struct bytes *key = bytes_from_str("YELLOW SUBMARINE");
	struct bytes *msg = bytes_from_str("rendez-vous at 6am");
	struct bytes *msg_tempered = bytes_from_str("rendez-vous at 6pm");
	if (key == NULL || msg == NULL || msg_tempered == NULL)
		munit_error("bytes_from_str");
	struct bytes *mac = md4_mac_keyed_prefix(key, msg);
	if (mac == NULL)
		munit_error("md4_mac_keyed_prefix");

	/* verify the message against its MAC */
	int ret = md4_mac_keyed_prefix_verify(key, msg, mac);
	munit_assert_int(ret, ==, 0);

	/* verify a tempered version of the message against the MAC */
	ret = md4_mac_keyed_prefix_verify(key, msg_tempered, mac);
	munit_assert_int(ret, ==, 1);

	/* attempt to MAC without knowing the key */
	struct bytes *hash = md4_hash(msg);
	if (hash == NULL)
		munit_error("md4_hash");
	ret = md4_mac_keyed_prefix_verify(key, msg, hash);
	munit_assert_int(ret, ==, 1);

	/* when NULL is given */
	ret = md4_mac_keyed_prefix_verify(NULL, msg,  mac);
	munit_assert_int(ret, ==, -1);
	ret = md4_mac_keyed_prefix_verify(key,  NULL, mac);
	munit_assert_int(ret, ==, -1);
	ret = md4_mac_keyed_prefix_verify(key,  msg,  NULL);
	munit_assert_int(ret, ==, -1);

	bytes_free(hash);
	bytes_free(mac);
	bytes_free(msg_tempered);
	bytes_free(msg);
	bytes_free(key);
	return (MUNIT_OK);
}


static MunitResult
test_hmac_sha1(const MunitParameter *params, void *data)
{
	/* HMAC-SHA1 test vectors, see RFC 2202 */
	const struct {
		size_t test_case;
		char *key;
		char *data;
		char *digest;
	} vectors[] = {
		{
			.test_case = 1,
			.key    = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			.data   = "4869205468657265", /* "Hi There" */
			.digest = "b617318655057264e28bc0b6fb378c8ef146be00",
		}, {
			.test_case = 2,
			.key    = "4a656665", /* "Jefe" */
			.data   = "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
				/* "what do ya want for nothing?" */
			.digest = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
		}, {
			.test_case = 3,
			.key    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			/* 0xdd repeated 50 times */
			.data   = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
			          "dddddddddddddddddddd",
			.digest = "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
		}, {
			.test_case = 4,
			.key    = "0102030405060708090a0b0c0d0e0f10111213141516171819",
			/* 0xcd repeated 50 times */
			.data   = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
			          "cdcdcdcdcdcdcdcdcdcd",
			.digest = "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
		}, {
			.test_case = 5,
			.key    = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
			.data   = "546573742057697468205472756e636174696f6e", /* "Test With Truncation" */
			.digest = "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
		}, {
			.test_case = 6,
			/* 0xaa repeated 80 times */
			.key    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			.data   = "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d20"
			          "48617368204b6579204669727374",
				/* "Test Using Larger Than Block-Size Key - Hash Key First" */
			.digest = "aa4ae5e15272d00e95705637ce8a3b55ed402112",
		}, {
			.test_case = 7,
			/* 0xaa repeated 80 times */
			.key    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			.data   = "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e"
			          "64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461",
				/* "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data" */
			.digest = "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
		}
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		struct bytes *key, *data, *expected;
		key      = bytes_from_hex(vectors[i].key);
		data     = bytes_from_hex(vectors[i].data);
		expected = bytes_from_hex(vectors[i].digest);
		if (key == NULL || data == NULL || expected == NULL)
			munit_error("bytes_from_hex");

		struct bytes *mac = hmac_sha1(key, data);
		munit_assert_not_null(mac);
		munit_assert_size(mac->len, ==, expected->len);
		munit_assert_memory_equal(mac->len, mac->data, expected->data);

		bytes_free(mac);
		bytes_free(expected);
		bytes_free(data);
		bytes_free(key);
	}

	/* when NULL is given */
	struct bytes *foo = bytes_from_str("foo");
	if (foo == NULL)
		munit_error("bytes_from_str");
	munit_assert_null(hmac_sha1(NULL, NULL));
	munit_assert_null(hmac_sha1(foo,  NULL));
	munit_assert_null(hmac_sha1(NULL, foo));

	bytes_free(foo);
	return (MUNIT_OK);
}


static MunitResult
test_hmac_md4(const MunitParameter *params, void *data)
{
	/* HMAC-SHA1 test vector taken from RFC 2202 and HMAC-MD4 result from
	   https://quickhash.com/ */
	const struct {
		size_t test_case;
		char *key;
		char *data;
		char *digest;
	} vectors[] = {
		{
			.test_case = 2,
			.key       = "4a656665", /* "Jefe" */
			.data      = "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
				/* "what do ya want for nothing?" */
			.digest    = "be192c588a8e914d8a59b474a828128f",
		},
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		struct bytes *key, *data, *expected;
		key      = bytes_from_hex(vectors[i].key);
		data     = bytes_from_hex(vectors[i].data);
		expected = bytes_from_hex(vectors[i].digest);
		if (key == NULL || data == NULL || expected == NULL)
			munit_error("bytes_from_hex");

		struct bytes *mac = hmac_md4(key, data);
		munit_assert_not_null(mac);
		munit_assert_size(mac->len, ==, md4_hashlength());
		munit_assert_memory_equal(mac->len, mac->data, expected->data);

		bytes_free(mac);
		bytes_free(expected);
		bytes_free(data);
		bytes_free(key);
	}

	/* when NULL is given */
	struct bytes *foo = bytes_from_str("foo");
	if (foo == NULL)
		munit_error("bytes_from_str");
	munit_assert_null(hmac_md4(NULL, NULL));
	munit_assert_null(hmac_md4(foo,  NULL));
	munit_assert_null(hmac_md4(NULL, foo));

	bytes_free(foo);
	return (MUNIT_OK);
}


static MunitResult
test_hmac_sha256(const MunitParameter *params, void *data)
{
	/* HMAC-SHA256 test vectors, see RFC 4231 */
	const struct {
		size_t test_case;
		char *key;
		char *data;
		char *digest;
	} vectors[] = {
		{
			.test_case = 1,
			.key    = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			.data   = "4869205468657265", /* "Hi There" */
			.digest = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
		}, {
			.test_case = 2,
			.key    = "4a656665", /* "Jefe" */
			.data   = "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
				/* "what do ya want for nothing?" */
			.digest = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
		}, {
			.test_case = 3,
			.key    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			/* 0xdd repeated 50 times */
			.data   = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
			          "dddddddddddddddddddd",
			.digest = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
		}, {
			.test_case = 4,
			.key    = "0102030405060708090a0b0c0d0e0f10111213141516171819",
			/* 0xcd repeated 50 times */
			.data   = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
			          "cdcdcdcdcdcdcdcdcdcd",
			.digest = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
		}, {
			.test_case = 5,
			.key    = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
			.data   = "546573742057697468205472756e636174696f6e", /* "Test With Truncation" */
			.digest = "a3b6167473100ee06e0c796c2955552b",
		}, {
			.test_case = 6,
			/* 0xaa repeated 131 times */
			.key    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			          "aaaaaaaaaaaaaaaaaaaaaa",
			.data   = "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d20"
			          "48617368204b6579204669727374",
				/* "Test Using Larger Than Block-Size Key - Hash Key First" */
			.digest = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
		}, {
			.test_case = 7,
			/* 0xaa repeated 131 times */
			.key    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			          "aaaaaaaaaaaaaaaaaaaaaa",
			.data   = "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b"
			          "2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a652064"
			          "6174612e20546865206b6579206e6565647320746f20626520686173686564206265666f72652062"
			          "65696e6720757365642062792074686520484d414320616c676f726974686d2e",
				/* "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm." */
			.digest = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
		}
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		struct bytes *key, *data, *expected;
		key      = bytes_from_hex(vectors[i].key);
		data     = bytes_from_hex(vectors[i].data);
		expected = bytes_from_hex(vectors[i].digest);
		if (key == NULL || data == NULL || expected == NULL)
			munit_error("bytes_from_hex");

		struct bytes *mac = hmac_sha256(key, data);
		munit_assert_not_null(mac);
		munit_assert_size(mac->len, ==, sha256_hashlength());
		munit_assert_memory_equal(expected->len, mac->data, expected->data);

		bytes_free(mac);
		bytes_free(expected);
		bytes_free(data);
		bytes_free(key);
	}

	/* when NULL is given */
	struct bytes *foo = bytes_from_str("foo");
	if (foo == NULL)
		munit_error("bytes_from_str");
	munit_assert_null(hmac_sha256(NULL, NULL));
	munit_assert_null(hmac_sha256(foo,  NULL));
	munit_assert_null(hmac_sha256(NULL, foo));

	bytes_free(foo);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_mac_suite_tests[] = {
	{ "sha1_mac_keyed_prefix",        test_sha1_mac_keyed_prefix,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "sha1_mac_keyed_prefix_verify", test_sha1_mac_keyed_prefix_verify, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "md4_mac_keyed_prefix",         test_md4_mac_keyed_prefix,         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "md4_mac_keyed_prefix_verify",  test_md4_mac_keyed_prefix_verify,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "hmac_sha1",   test_hmac_sha1,   NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "hmac_md4",    test_hmac_md4,    NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "hmac_sha256", test_hmac_sha256, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
