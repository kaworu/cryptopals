/*
 * test_cookie.c
 */

#include "munit.h"
#include "cookie.h"


static MunitResult
test_cookie_alloc(const MunitParameter *params, void *data)
{
	struct cookie *cookie = NULL;

	cookie = cookie_alloc();
	munit_assert_not_null(cookie);

	cookie_free(cookie);
	return (MUNIT_OK);
}


/* Error conditions */
static MunitResult
test_cookie_decode_0(const MunitParameter *params, void *data)
{
	/* when NULL is given */
	munit_assert_null(cookie_decode(NULL));
	/* when the encoded string has no k=v */
	munit_assert_null(cookie_decode("foobar"));
	/* `=' twice */
	munit_assert_null(cookie_decode("foo=bar=baz"));
	/* illegal character */
	munit_assert_null(cookie_decode("foo=bar?"));

	return (MUNIT_OK);
}


static MunitResult
test_cookie_decode_1(const MunitParameter *params, void *data)
{
	struct cookie *decoded = NULL;

	/*
	 * The following cases are tolerated at the moment by our implementation
	 * because strtok_r(3) only yield the non-empty tokens.
	 */

	/* leading `&' */
	decoded = cookie_decode("&foo=bar");
	munit_assert_not_null(decoded);
	cookie_free(decoded);
	/* double `&' */
	decoded = cookie_decode("foo=bar&&baz=qux");
	munit_assert_not_null(decoded);
	cookie_free(decoded);
	/* trailing `&' */
	decoded = cookie_decode("foo=bar&");
	munit_assert_not_null(decoded);
	cookie_free(decoded);

	return (MUNIT_OK);
}


static MunitResult
test_cookie_decode_2(const MunitParameter *params, void *data)
{
	size_t count = 0;
	struct cookie *decoded = NULL;

	decoded = cookie_decode("foo%3d=%3Dbar%26");
	munit_assert_not_null(decoded);
	if (cookie_count(decoded, &count) != 0)
		munit_error("cookie_count");
	munit_assert_size(count, ==, 1);
	const struct cookie_kv *kv = cookie_at(decoded, 0);
	munit_assert_not_null(kv);
	munit_assert_string_equal(cookie_kv_key(kv), "foo=");
	munit_assert_string_equal(cookie_kv_value(kv), "=bar&");

	cookie_free(decoded);
	return (MUNIT_OK);
}


static MunitResult
test_cookie_count(const MunitParameter *params, void *data)
{
	struct cookie *cookie = NULL;
	size_t count = 0;

	cookie = cookie_alloc();
	if (cookie == NULL)
		munit_error("cookie_alloc");

	munit_assert_int(cookie_count(cookie, &count), ==, 0);
	munit_assert_size(count, ==, 0);

	for (size_t i = 1; i <= 128; i++) {
		if (cookie_append(cookie, "foo", "bar") != 0)
			munit_error("cookie_append");
		munit_assert_int(cookie_count(cookie, &count), ==, 0);
		munit_assert_size(count, ==, i);
	}

	/* when NULL is given */
	munit_assert_int(cookie_count(NULL, &count), ==, -1);
	munit_assert_int(cookie_count(cookie, NULL), ==, 0);

	cookie_free(cookie);
	return (MUNIT_OK);
}


static MunitResult
test_cookie_at(const MunitParameter *params, void *data)
{
	struct cookie *cookie = NULL;

	const struct {
		char *key;
		char *value;
	} vectors[] = {
		{ .key = "foo", .value = "bar" },
		{ .key = "baz", .value = "qux" },
		{ .key = "zap", .value = "zazzle" },
	};
	const size_t nelem = sizeof(vectors) / sizeof(*vectors);

	cookie = cookie_alloc();
	if (cookie == NULL)
		munit_error("cookie_alloc");

	for (size_t i = 0; i < nelem; i++) {
		const char *key   = vectors[i].key;
		const char *value = vectors[i].value;
		if (cookie_append(cookie, key, value) != 0)
			munit_error("cookie_append");
	}

	for (size_t i = 0; i < nelem; i++) {
		const char *key   = vectors[i].key;
		const char *value = vectors[i].value;
		const struct cookie_kv *kv = cookie_at(cookie, i);
		munit_assert_not_null(kv);
		munit_assert_string_equal(cookie_kv_key(kv), key);
		munit_assert_string_equal(cookie_kv_value(kv), value);
	}

	/* when NULL is given */
	munit_assert_null(cookie_at(NULL, 0));
	/* when index is out of bound */
	munit_assert_null(cookie_at(cookie, nelem));

	cookie_free(cookie);
	return (MUNIT_OK);
}


static MunitResult
test_cookie_get_0(const MunitParameter *params, void *data)
{
	struct cookie *cookie = NULL;

	const struct {
		char *key;
		char *value;
	} vectors[] = {
		{ .key = "foo", .value = "bar" },
		{ .key = "baz", .value = "qux" },
		{ .key = "zap", .value = "zazzle" },
	};
	const size_t nelem = sizeof(vectors) / sizeof(*vectors);

	cookie = cookie_alloc();
	if (cookie == NULL)
		munit_error("cookie_alloc");

	for (size_t i = 0; i < nelem; i++) {
		const char *key   = vectors[i].key;
		const char *value = vectors[i].value;
		if (cookie_append(cookie, key, value) != 0)
			munit_error("cookie_append");
	}

	for (size_t i = 0; i < nelem; i++) {
		const char *key   = vectors[i].key;
		const char *value = vectors[i].value;
		const struct cookie_kv *kv = cookie_get(cookie, key);
		munit_assert_not_null(kv);
		munit_assert_string_equal(cookie_kv_key(kv), key);
		munit_assert_string_equal(cookie_kv_value(kv), value);
	}

	/* when NULL is given */
	munit_assert_null(cookie_get(NULL, "foo"));
	munit_assert_null(cookie_get(cookie, NULL));
	/* when index is not found */
	munit_assert_null(cookie_get(cookie, "invalid-key"));

	cookie_free(cookie);
	return (MUNIT_OK);
}


static MunitResult
test_cookie_get_1(const MunitParameter *params, void *data)
{
	int err = 0;
	struct cookie *cookie = NULL;

	cookie = cookie_alloc();
	if (cookie == NULL)
		munit_error("cookie_alloc");

	err |= cookie_append(cookie, "foo", "bar");
	err |= cookie_append(cookie, "baz", "qux");
	err |= cookie_append(cookie, "zap", "zazzle");
	err |= cookie_append(cookie, "baz", "hidden");
	if (err)
		munit_error("cookie_append");

	/* check that first given is the approach taken when getting "baz" */
	const struct cookie_kv *kv = cookie_get(cookie, "baz");
	munit_assert_not_null(kv);
	munit_assert_string_equal(cookie_kv_key(kv), "baz");
	munit_assert_string_equal(cookie_kv_value(kv), "qux");

	cookie_free(cookie);
	return (MUNIT_OK);
}


/* Error conditions */
static MunitResult
test_cookie_encode_0(const MunitParameter *params, void *data)
{
	/* when NULL is given */
	munit_assert_null(cookie_encode(NULL));

	return (MUNIT_OK);
}


static MunitResult
test_cookie_encode_1(const MunitParameter *params, void *data)
{
	char *encoded = NULL;
	struct cookie *cookie = NULL;

	cookie = cookie_alloc();
	if (cookie == NULL)
		munit_error("cookie_alloc");
	encoded = cookie_encode(cookie);
	munit_assert_not_null(encoded);
	munit_assert_string_equal(encoded, "");
	free(encoded);

	if (cookie_append(cookie, "foo", "bar") != 0)
		munit_error("cookie_append");
	encoded = cookie_encode(cookie);
	munit_assert_not_null(encoded);
	munit_assert_string_equal(encoded, "foo=bar");
	free(encoded);

	if (cookie_append(cookie, "baz", "qux") != 0)
		munit_error("cookie_append");
	encoded = cookie_encode(cookie);
	munit_assert_not_null(encoded);
	munit_assert_string_equal(encoded, "foo=bar&baz=qux");
	free(encoded);

	if (cookie_append(cookie, "zap", "zazzle") != 0)
		munit_error("cookie_append");
	encoded = cookie_encode(cookie);
	munit_assert_not_null(encoded);
	munit_assert_string_equal(encoded, "foo=bar&baz=qux&zap=zazzle");
	free(encoded);

	cookie_free(cookie);
	return (MUNIT_OK);
}


static MunitResult
test_cookie_encode_2(const MunitParameter *params, void *data)
{
	char *encoded = NULL;
	struct cookie *cookie = NULL;

	cookie = cookie_alloc();
	if (cookie == NULL)
		munit_error("cookie_alloc");
	if (cookie_append(cookie, "role=admin", "") != 0)
		munit_error("cookie_append");
	encoded = cookie_encode(cookie);
	munit_assert_not_null(encoded);
	/* workaround https://github.com/nemequ/munit/pull/42 */
	const char *expected = "role%3Dadmin=";
	munit_assert_string_equal(encoded, expected);

	free(encoded);
	cookie_free(cookie);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_cookie_suite_tests[] = {
	{ "cookie_alloc",    test_cookie_alloc,    NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "cookie_decode-0", test_cookie_decode_0, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "cookie_decode-1", test_cookie_decode_1, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "cookie_decode-2", test_cookie_decode_2, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "cookie_count",    test_cookie_count,    NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "cookie_at",       test_cookie_at,       NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "cookie_get-0",    test_cookie_get_0,    NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "cookie_get-1",    test_cookie_get_1,    NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "cookie_encode-0", test_cookie_encode_0, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "cookie_encode-1", test_cookie_encode_1, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "cookie_encode-2", test_cookie_encode_2, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
