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


/* The test suite. */
MunitTest test_mac_suite_tests[] = {
	{ "sha1_mac_keyed_prefix",        test_sha1_mac_keyed_prefix,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "sha1_mac_keyed_prefix_verify", test_sha1_mac_keyed_prefix_verify, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "md4_mac_keyed_prefix",         test_md4_mac_keyed_prefix,         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "md4_mac_keyed_prefix_verify",  test_md4_mac_keyed_prefix_verify,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
