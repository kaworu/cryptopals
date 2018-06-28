/*
 * test_break_mac.c
 */
#include "munit.h"
#include "helpers.h"
#include "sha1.h"
#include "mac.h"
#include "break_mac.h"


/* Set 4 / Challenge 29 */
static MunitResult
test_extend_sha1_mac_keyed_prefix(const MunitParameter *params, void *data)
{
	struct bytes *key = bytes_randomized(munit_rand_int_range(64, 128));
	if (key == NULL)
		munit_error("bytes_randomized");
	struct bytes *msg = bytes_from_str("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon");
	if (msg == NULL)
		munit_error("bytes_from_str");
	struct bytes *mac = sha1_mac_keyed_prefix(key, msg);
	if (mac == NULL)
		munit_error("sha1_mac_keyed_prefix");

	/* verify the message against its MAC */
	int ret = sha1_mac_keyed_prefix_verify(key, msg, mac);
	munit_assert_int(ret, ==, 0);

	/* perform the message extension */
	struct bytes *ext_msg = NULL, *ext_mac = NULL;
	ret = extend_sha1_mac_keyed_prefix(key, msg, mac,
		    &ext_msg, &ext_mac);
	munit_assert_int(ret, ==, 0);
	munit_assert_not_null(ext_msg);
	munit_assert_not_null(ext_mac);

	/* ensure that the extension has injected the admin=true payload */
	struct bytes *admin = bytes_from_str(";admin=true;");
	if (admin == NULL)
		munit_error("bytes_from_str");
	ret = bytes_find(ext_msg, admin, NULL);
	munit_assert_int(ret, ==, 0);

	/* verify the extended message against its forged MAC */
	ret = sha1_mac_keyed_prefix_verify(key, ext_msg, ext_mac);
	munit_assert_int(ret, ==, 0);

	bytes_free(admin);
	bytes_free(ext_mac);
	bytes_free(ext_msg);
	bytes_free(mac);
	bytes_free(msg);
	bytes_free(key);
	return (MUNIT_OK);
}


/* Set 4 / Challenge 30 */
static MunitResult
test_extend_md4_mac_keyed_prefix(const MunitParameter *params, void *data)
{
	struct bytes *key = bytes_randomized(munit_rand_int_range(64, 128));
	if (key == NULL)
		munit_error("bytes_randomized");
	struct bytes *msg = bytes_from_str("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon");
	if (msg == NULL)
		munit_error("bytes_from_str");
	struct bytes *mac = md4_mac_keyed_prefix(key, msg);
	if (mac == NULL)
		munit_error("md4_mac_keyed_prefix");

	/* verify the message against its MAC */
	int ret = md4_mac_keyed_prefix_verify(key, msg, mac);
	munit_assert_int(ret, ==, 0);

	/* perform the message extension */
	struct bytes *ext_msg = NULL, *ext_mac = NULL;
	ret = extend_md4_mac_keyed_prefix(key, msg, mac,
		    &ext_msg, &ext_mac);
	munit_assert_int(ret, ==, 0);
	munit_assert_not_null(ext_msg);
	munit_assert_not_null(ext_mac);

	/* ensure that the extension has injected the admin=true payload */
	struct bytes *admin = bytes_from_str(";admin=true;");
	if (admin == NULL)
		munit_error("bytes_from_str");
	ret = bytes_find(ext_msg, admin, NULL);
	munit_assert_int(ret, ==, 0);

	/* verify the extended message against its forged MAC */
	ret = md4_mac_keyed_prefix_verify(key, ext_msg, ext_mac);
	munit_assert_int(ret, ==, 0);

	bytes_free(admin);
	bytes_free(ext_mac);
	bytes_free(ext_msg);
	bytes_free(mac);
	bytes_free(msg);
	bytes_free(key);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_break_mac_suite_tests[] = {
	{ "sha1_length_extension", test_extend_sha1_mac_keyed_prefix, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "md4_length_extension",  test_extend_md4_mac_keyed_prefix,  srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
