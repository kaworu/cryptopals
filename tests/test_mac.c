/*
 * test_mac.c
 */
#include "munit.h"
#include "sha1.h"
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
		munit_assert_size(mac->len, ==, 160 / 8);
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

	int ret = sha1_mac_keyed_prefix_verify(key, msg, mac);
	munit_assert_int(ret, ==, 0);
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


/* The test suite. */
MunitTest test_mac_suite_tests[] = {
	{ "sha1_mac_keyed_prefix",        test_sha1_mac_keyed_prefix,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "sha1_mac_keyed_prefix_verify", test_sha1_mac_keyed_prefix_verify, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
