/*
 * test_mac.c
 */
#include "munit.h"
#include "sha1.h"
#include "md4.h"
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
		size_t key_len;
		char *data;
		size_t data_len;
		char *digest;
	} vectors[] = {
		{
			.test_case = 1,
			.key       = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
			.key_len   = 20,
			.data      = "Hi There",
			.data_len  = 8,
			.digest    = "\xb6\x17\x31\x86\x55\x05\x72\x64\xe2\x8b\xc0\xb6\xfb\x37\x8c\x8e\xf1\x46\xbe\x00",
		}, {
			.test_case = 2,
			.key       = "Jefe",
			.key_len   = 4,
			.data      = "what do ya want for nothing?",
			.data_len  = 28,
			.digest    = "\xef\xfc\xdf\x6a\xe5\xeb\x2f\xa2\xd2\x74\x16\xd5\xf1\x84\xdf\x9c\x25\x9a\x7c\x79",
		}, {
			.test_case = 3,
			.key       = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
			.key_len   = 20,
			/* 0xdd repeated 50 times */
			.data      = "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
			            "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
			            "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd",
			.data_len  = 50,
			.digest    = "\x12\x5d\x73\x42\xb9\xac\x11\xcd\x91\xa3\x9a\xf4\x8a\xa1\x7b\x4f\x63\xf1\x75\xd3",
		}, {
			.test_case = 4,
			.key       = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
			            "\x15\x16\x17\x18\x19",
			.key_len   = 25,
			/* 0xcd repeated 50 times */
			.data      = "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
			            "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
			            "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd",
			.data_len  = 50,
			.digest    = "\x4c\x90\x07\xf4\x02\x62\x50\xc6\xbc\x84\x14\xf9\xbf\x50\xc8\x6c\x2d\x72\x35\xda",
		}, {
			.test_case = 5,
			.key       = "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c",
			.key_len   = 20,
			.data      = "Test With Truncation",
			.data_len  = 20,
			.digest    = "\x4c\x1a\x03\x42\x4b\x55\xe0\x7f\xe7\xf2\x7b\xe1\xd5\x8b\xb9\x32\x4a\x9a\x5a\x04",
		}, {
			.test_case = 6,
			/* 0xaa repeated 80 times */
			.key       = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
			             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
			             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
			             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
			.key_len   = 80,
			.data      = "Test Using Larger Than Block-Size Key - Hash Key First",
			.data_len  = 54,
			.digest    = "\xaa\x4a\xe5\xe1\x52\x72\xd0\x0e\x95\x70\x56\x37\xce\x8a\x3b\x55\xed\x40\x21\x12",
		}, {
			.test_case = 7,
			/* 0xaa repeated 80 times */
			.key       = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
			             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
			             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
			             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
			.key_len   = 80,
			.data      = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
			.data_len  = 73,
			.digest    = "\xe8\xe9\x9d\x0f\x45\x23\x7d\x78\x6d\x6b\xba\xa7\x96\x5c\x78\x08\xbb\xff\x1a\x91",
		}
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		struct bytes *key, *data, *expected;
		key      = bytes_from_raw(vectors[i].key, vectors[i].key_len);
		data     = bytes_from_raw(vectors[i].data, vectors[i].data_len);
		expected = bytes_from_raw(vectors[i].digest, sha1_hashlength());
		if (key == NULL || data == NULL || expected == NULL)
			munit_error("bytes_from_raw");

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
		size_t key_len;
		char *data;
		size_t data_len;
		char *digest;
	} vectors[] = {
		{
			.test_case = 2,
			.key       = "Jefe",
			.key_len   = 4,
			.data      = "what do ya want for nothing?",
			.data_len  = 28,
			.digest    = "\xbe\x19\x2c\x58\x8a\x8e\x91\x4d\x8a\x59\xb4\x74\xa8\x28\x12\x8f",
		},
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		struct bytes *key, *data, *expected;
		key      = bytes_from_raw(vectors[i].key, vectors[i].key_len);
		data     = bytes_from_raw(vectors[i].data, vectors[i].data_len);
		expected = bytes_from_raw(vectors[i].digest, md4_hashlength());
		if (key == NULL || data == NULL || expected == NULL)
			munit_error("bytes_from_raw");

		struct bytes *mac = hmac_md4(key, data);
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
	munit_assert_null(hmac_md4(NULL, NULL));
	munit_assert_null(hmac_md4(foo,  NULL));
	munit_assert_null(hmac_md4(NULL, foo));

	bytes_free(foo);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_mac_suite_tests[] = {
	{ "sha1_mac_keyed_prefix",        test_sha1_mac_keyed_prefix,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "sha1_mac_keyed_prefix_verify", test_sha1_mac_keyed_prefix_verify, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "md4_mac_keyed_prefix",         test_md4_mac_keyed_prefix,         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "md4_mac_keyed_prefix_verify",  test_md4_mac_keyed_prefix_verify,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "hmac_sha1", test_hmac_sha1,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "hmac_md4",  test_hmac_md4,   NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
