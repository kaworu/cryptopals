/*
 * test_mpi.c
 */
#include "munit.h"
#include "helpers.h"

#include "mpi.h"
#include "compat.h"


/* helper to create a mpi from an int */
static struct mpi *
my_mpi_from_int(int x)
{
	/*
	 * Use decimal printf(3) format so that negative values are handled
	 * correctly.
	 */
	char *buf = NULL;
	struct mpi *num = NULL;
	int success = 0;

	if (asprintf(&buf, "%d", x) == -1)
		goto cleanup;

	num = mpi_from_dec(buf);
	if (num == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	free(buf);
	if (!success) {
		mpi_free(num);
		num = NULL;
	}
	return (num);
}


static MunitResult
test_mpi_skip(const MunitParameter *params, void *data)
{
	return (MUNIT_SKIP);
}


static MunitResult
test_mpi_zero(const MunitParameter *params, void *data)
{
	struct mpi *zero = mpi_zero();
	struct mpi *hex  = mpi_from_hex("0");
	struct mpi *dec  = mpi_from_dec("0");
	if (hex == NULL)
		munit_error("mpi_from_hex");
	if (dec == NULL)
		munit_error("mpi_from_dec");

	munit_assert_not_null(zero);
	munit_assert_int(mpi_cmp(zero, hex), ==, 0);
	munit_assert_int(mpi_cmp(zero, dec), ==, 0);

	mpi_free(dec);
	mpi_free(hex);
	mpi_free(zero);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_one(const MunitParameter *params, void *data)
{
	struct mpi *one  = mpi_one();
	struct mpi *hex  = mpi_from_hex("1");
	struct mpi *dec  = mpi_from_dec("1");
	if (hex == NULL)
		munit_error("mpi_from_hex");
	if (dec == NULL)
		munit_error("mpi_from_dec");

	munit_assert_not_null(one);
	munit_assert_int(mpi_cmp(one, hex), ==, 0);
	munit_assert_int(mpi_cmp(one, dec), ==, 0);

	mpi_free(dec);
	mpi_free(hex);
	mpi_free(one);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_from_hex_and_dec(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		char *expected;
	} vectors[] = {
		{ .input = "0",     .expected = "0"     },
		/* https://github.com/openssl/openssl/commit/01c09f9fde5793e0b3712d602b02e2aed4908e8d */
		/*{ .input =  "-0",   .expected = "0"     },*/
		{ .input = "1",     .expected = "1"     },
		{ .input = "-1",    .expected = "-1"    },
		{ .input = "F",     .expected = "15"    },
		{ .input = "10",    .expected = "16"    },
		{ .input = "F00",   .expected = "3840"  },
		{ .input = "ABCD",  .expected = "43981" },
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input    = vectors[i].input;
		const char *expected = vectors[i].expected;

		struct mpi *hex = mpi_from_hex(input);
		struct mpi *dec = mpi_from_dec(expected);
		munit_assert_not_null(dec);
		munit_assert_not_null(hex);
		munit_assert_int(mpi_cmp(dec, hex), ==, 0);

		mpi_free(dec);
		mpi_free(hex);
	}

	/* when NULL is given */
	munit_assert_null(mpi_from_hex(NULL));
	munit_assert_null(mpi_from_dec(NULL));
	/* invalid values */
	munit_assert_null(mpi_from_hex("mouhahaha"));
	munit_assert_null(mpi_from_dec("mouhahaha"));

	return (MUNIT_OK);
}


static MunitResult
test_mpi_from_bytes_be(const MunitParameter *params, void *data)
{
	for (size_t i = 1; i < 100; i++) {
		struct bytes *buf = bytes_randomized(i);
		if (buf == NULL)
			munit_error("bytes_randomized");

		/*
		 * prevent the most significant byte to be zero, because it
		 * would be "lost" when converted to a mpi number.
		 */
		buf->data[0] |= 0x1;

		char *hex = bytes_to_hex(buf);
		if (hex == NULL)
			munit_error("bytes_to_hex");
		struct mpi *expected = mpi_from_hex(hex);
		if (expected == NULL)
			munit_error("mpi_from_hex");

		struct mpi *result = mpi_from_bytes_be(buf);
		munit_assert_not_null(result);
		munit_assert_int(mpi_cmp(expected, result), ==, 0);

		mpi_free(result);
		mpi_free(expected);
		free(hex);
		bytes_free(buf);
	}

	/* when NULL is given */
	munit_assert_null(mpi_from_bytes_be(NULL));

	return (MUNIT_OK);
}


static MunitResult
test_mpi_dup(const MunitParameter *params, void *data)
{
	struct mpi *n = mpi_rand_odd_top2(128);
	if (n == NULL)
		munit_error("mpi_rand_odd_top2");

	struct mpi *cpy = mpi_dup(n);
	munit_assert_not_null(cpy);
	munit_assert_int(mpi_cmp(n, cpy), ==, 0);

	/* when NULL is given */
	munit_assert_null(mpi_dup(NULL));

	mpi_free(cpy);
	mpi_free(n);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_cmp(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 100; i++) {
		const int xi = munit_rand_int_range(INT_MIN, INT_MAX);
		const int yi = munit_rand_int_range(INT_MIN, INT_MAX);
		struct mpi *x = my_mpi_from_int(xi);
		struct mpi *y = my_mpi_from_int(yi);
		if (x == NULL || y == NULL)
			munit_error("my_mpi_from_int");

		const int x_cmp_y = (xi == yi ? 0 : (xi > yi ? 1 : -1));
		const int y_cmp_x = -(x_cmp_y);
		munit_assert_int(mpi_cmp(x, y), ==, x_cmp_y);
		munit_assert_int(mpi_cmp(y, x), ==, y_cmp_x);
		munit_assert_int(mpi_cmp(x, x), ==, 0);
		munit_assert_int(mpi_cmp(y, y), ==, 0);

		mpi_free(y);
		mpi_free(x);
	}

	struct mpi *zero = mpi_zero();
	if (zero == NULL)
		munit_error("mpi_zero");
	/* when NULL is given */
	munit_assert_int(mpi_cmp(NULL, zero), ==, INT_MIN);
	munit_assert_int(mpi_cmp(zero, NULL), ==, INT_MIN);
	munit_assert_int(mpi_cmp(NULL, NULL), ==, INT_MIN);
	mpi_free(zero);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_test_zero(const MunitParameter *params, void *data)
{
	struct mpi *zero      = mpi_from_dec("0");
	struct mpi *one       = mpi_from_dec("1");
	struct mpi *minus_one = mpi_from_dec("-1");
	if (zero == NULL || one == NULL || minus_one == NULL)
		munit_error("mpi_from_dec");

	munit_assert_int(mpi_test_zero(zero),      ==, 0);
	munit_assert_int(mpi_test_zero(one),       ==, 1);
	munit_assert_int(mpi_test_zero(minus_one), ==, 1);
	/* when NULL is given */
	munit_assert_int(mpi_test_zero(NULL), ==, 1);

	mpi_free(minus_one);
	mpi_free(one);
	mpi_free(zero);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_test_one(const MunitParameter *params, void *data)
{
	struct mpi *zero      = mpi_from_dec("0");
	struct mpi *one       = mpi_from_dec("1");
	struct mpi *minus_one = mpi_from_dec("-1");
	if (zero == NULL || one == NULL || minus_one == NULL)
		munit_error("mpi_from_dec");

	munit_assert_int(mpi_test_one(zero),      ==, 1);
	munit_assert_int(mpi_test_one(one),       ==, 0);
	munit_assert_int(mpi_test_one(minus_one), ==, 1);
	/* when NULL is given */
	munit_assert_int(mpi_test_one(NULL), ==, 1);

	mpi_free(minus_one);
	mpi_free(one);
	mpi_free(zero);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_add(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 100; i++) {
		const int ai = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int bi = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);

		int ri = (ai + bi);

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *b = my_mpi_from_int(bi);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || b == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		struct mpi *result = mpi_add(a, b);
		munit_assert_not_null(result);
		munit_assert_int(mpi_cmp(result, r), ==, 0);

		mpi_free(result);
		mpi_free(r);
		mpi_free(b);
		mpi_free(a);
	}

	struct mpi *one = mpi_one();
	if (one == NULL)
		munit_error("mpi_one");
	/* when NULL is given */
	munit_assert_null(mpi_add(NULL, one));
	munit_assert_null(mpi_add(one, NULL));
	munit_assert_null(mpi_add(NULL, NULL));

	mpi_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_mod_add(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 100; i++) {
		const int ai = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int bi = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int mi = munit_rand_int_range(2, 16);

		int ri = (ai + bi) % mi;
		if (ri < 0)
			ri += mi;

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *b = my_mpi_from_int(bi);
		struct mpi *m = my_mpi_from_int(mi);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || b == NULL || m == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		struct mpi *result = mpi_mod_add(a, b, m);
		munit_assert_not_null(result);
		munit_assert_int(mpi_cmp(result, r), ==, 0);

		mpi_free(result);
		mpi_free(r);
		mpi_free(m);
		mpi_free(b);
		mpi_free(a);
	}

	struct mpi *one = mpi_one();
	if (one == NULL)
		munit_error("mpi_one");
	/* when NULL is given */
	munit_assert_null(mpi_mod_add(NULL, one, one));
	munit_assert_null(mpi_mod_add(one, NULL, one));
	munit_assert_null(mpi_mod_add(one, one, NULL));
	munit_assert_null(mpi_mod_add(NULL, NULL, one));
	munit_assert_null(mpi_mod_add(NULL, one, NULL));
	munit_assert_null(mpi_mod_add(one, NULL, NULL));
	munit_assert_null(mpi_mod_add(NULL, NULL, NULL));

	mpi_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_sub(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 100; i++) {
		const int ai = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int bi = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int ri = ai - bi;

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *b = my_mpi_from_int(bi);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || b == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		struct mpi *result = mpi_sub(a, b);

		munit_assert_not_null(result);
		munit_assert_int(mpi_cmp(result, r), ==, 0);

		mpi_free(result);
		mpi_free(r);
		mpi_free(b);
		mpi_free(a);
	}

	struct mpi *one = mpi_one();
	if (one == NULL)
		munit_error("mpi_one");
	/* when NULL is given */
	munit_assert_null(mpi_sub(one, NULL));
	munit_assert_null(mpi_sub(NULL, one));
	munit_assert_null(mpi_sub(NULL, NULL));

	mpi_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_mul(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 100; i++) {
		const int ai = munit_rand_int_range(-256, 256);
		const int bi = munit_rand_int_range(-256, 256);

		int ri = (ai * bi);

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *b = my_mpi_from_int(bi);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || b == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		struct mpi *result = mpi_mul(a, b);
		munit_assert_not_null(result);
		munit_assert_int(mpi_cmp(result, r), ==, 0);

		mpi_free(result);
		mpi_free(r);
		mpi_free(b);
		mpi_free(a);
	}

	struct mpi *one = mpi_one();
	if (one == NULL)
		munit_error("mpi_one");
	/* when NULL is given */
	munit_assert_null(mpi_mul(NULL, one));
	munit_assert_null(mpi_mul(one, NULL));
	munit_assert_null(mpi_mul(NULL, NULL));

	mpi_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_mod_mul(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 100; i++) {
		const int ai = munit_rand_int_range(-256, 256);
		const int bi = munit_rand_int_range(-256, 256);
		const int mi = munit_rand_int_range(2, 16);

		int ri = (ai * bi) % mi;
		if (ri < 0)
			ri += mi;

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *b = my_mpi_from_int(bi);
		struct mpi *m = my_mpi_from_int(mi);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || b == NULL || m == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		struct mpi *result = mpi_mod_mul(a, b, m);
		munit_assert_not_null(result);
		munit_assert_int(mpi_cmp(result, r), ==, 0);

		mpi_free(result);
		mpi_free(r);
		mpi_free(m);
		mpi_free(b);
		mpi_free(a);
	}

	struct mpi *one = mpi_one();
	if (one == NULL)
		munit_error("mpi_one");
	/* when NULL is given */
	munit_assert_null(mpi_mod_mul(NULL, one, one));
	munit_assert_null(mpi_mod_mul(one, NULL, one));
	munit_assert_null(mpi_mod_mul(one, one, NULL));
	munit_assert_null(mpi_mod_mul(NULL, NULL, one));
	munit_assert_null(mpi_mod_mul(NULL, one, NULL));
	munit_assert_null(mpi_mod_mul(one, NULL, NULL));
	munit_assert_null(mpi_mod_mul(NULL, NULL, NULL));

	mpi_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_mod_exp(const MunitParameter *params, void *data)
{
	/* example from https://en.wikipedia.org/wiki/Modular_exponentiation */
	struct mpi *base = mpi_from_dec("4");
	struct mpi *exp  = mpi_from_dec("13");
	struct mpi *mod  = mpi_from_dec("497");
	struct mpi *expected = mpi_from_dec("445");

	struct mpi *result = mpi_mod_exp(base, exp, mod);
	munit_assert_not_null(result);
	munit_assert_int(mpi_cmp(result, expected), ==, 0);
	mpi_free(result);

	/* when NULL is given */
	munit_assert_null(mpi_mod_exp(NULL, exp, mod));
	munit_assert_null(mpi_mod_exp(base, NULL, mod));
	munit_assert_null(mpi_mod_exp(base, exp, NULL));

	mpi_free(expected);
	mpi_free(mod);
	mpi_free(exp);
	mpi_free(base);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_to_bytes_be(const MunitParameter *params, void *data)
{
	for (size_t i = 1; i < 100; i++) {
		struct bytes *buf = bytes_randomized(i);
		if (buf == NULL)
			munit_error("bytes_randomized");

		/*
		 * prevent the most significant byte to be zero, because it
		 * would be "lost" when converted to a mpi number.
		 */
		buf->data[0] |= 0x1;

		char *hex = bytes_to_hex(buf);
		if (hex == NULL)
			munit_error("bytes_to_hex");
		struct mpi *num = mpi_from_hex(hex);
		if (num == NULL)
			munit_error("mpi_from_hex");
		struct bytes *result = mpi_to_bytes_be(num);

		munit_assert_not_null(result);
		munit_assert_size(result->len, ==, buf->len);
		munit_assert_memory_equal(buf->len, result->data, buf->data);

		bytes_free(result);
		mpi_free(num);
		free(hex);
		bytes_free(buf);
	}

	/* when zero is given */
	struct mpi *z = mpi_zero();
	if (z == NULL)
		munit_error("mpi_zero");
	struct bytes *zbuf = mpi_to_bytes_be(z);
	munit_assert_not_null(zbuf);
	munit_assert_size(zbuf->len, ==, 1);
	munit_assert_uint8(zbuf->data[0], ==, 0x00);

	/* when NULL is given */
	munit_assert_null(mpi_to_dec(NULL));

	bytes_free(zbuf);
	mpi_free(z);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_to_dec(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		char *expected;
	} vectors[] = {
		{ .input = "0",     .expected = "0"     },
		/* https://github.com/openssl/openssl/commit/01c09f9fde5793e0b3712d602b02e2aed4908e8d */
		/*{ .input =  "-0",   .expected = "0"     },*/
		{ .input = "1",     .expected = "1"     },
		{ .input = "-1",    .expected = "-1"    },
		{ .input = "F",     .expected = "15"    },
		{ .input = "10",    .expected = "16"    },
		{ .input = "F00",   .expected = "3840"  },
		{ .input = "ABCD",  .expected = "43981" },
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input    = vectors[i].input;
		const char *expected = vectors[i].expected;
		struct mpi *n = mpi_from_hex(input);
		if (n == NULL)
			munit_error("mpi_from_hex");

		char *res = mpi_to_dec(n);
		munit_assert_not_null(res);
		munit_assert_string_equal(res, expected);

		free(res);
		mpi_free(n);
	}

	/* when NULL is given */
	munit_assert_null(mpi_to_dec(NULL));

	return (MUNIT_OK);
}


static MunitResult
test_mpi_to_hex(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		char *expected;
	} vectors[] = {
		{ .input = "0",     .expected = "0"    },
		/* https://github.com/openssl/openssl/commit/01c09f9fde5793e0b3712d602b02e2aed4908e8d */
		/*{ .input =  "-0",   .expected = "0"    },*/
		{ .input = "1",     .expected = "1"    },
		{ .input = "-1",    .expected = "-1"   },
		{ .input = "15",    .expected = "F"    },
		{ .input = "16",    .expected = "10"   },
		{ .input = "3840",  .expected = "F00"  },
		{ .input = "43981", .expected = "ABCD" },
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input    = vectors[i].input;
		const char *expected = vectors[i].expected;
		struct mpi *n = mpi_from_dec(input);
		if (n == NULL)
			munit_error("mpi_from_dec");

		char *res = mpi_to_hex(n);
		munit_assert_not_null(res);
		munit_assert_string_equal(res, expected);

		free(res);
		mpi_free(n);
	}

	/* when NULL is given */
	munit_assert_null(mpi_to_hex(NULL));

	return (MUNIT_OK);
}


static MunitResult
test_mpi_probable_prime(const MunitParameter *params, void *data)
{
	for (size_t bits = 2; bits <= 1024; bits *= 2) {
		struct mpi *n = mpi_probable_prime(bits);
		munit_assert_not_null(n);
		munit_assert_int(mpi_test_probably_prime(n), ==, 0);
		mpi_free(n);
	}

	/* error cases */
	munit_assert_null(mpi_probable_prime(1));
	munit_assert_null(mpi_probable_prime((size_t)INT_MAX + 1));

	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_mpi_suite_tests[] = {
	{ "mpi_zero",           test_mpi_zero,             NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_one",            test_mpi_one,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_from_hex",       test_mpi_from_hex_and_dec, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_from_bytes",     test_mpi_from_bytes_be,    srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_rand_range",     test_mpi_skip,             NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_rand_range_from_zero_to",     test_mpi_skip,             NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_rand_range_from_one_to",     test_mpi_skip,             NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_rand_odd_top2",  test_mpi_skip,             NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_dup",            test_mpi_dup,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_setn",           test_mpi_skip,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_probable_prime", test_mpi_probable_prime,   srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_cmp",            test_mpi_cmp,              srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_testn",          test_mpi_skip,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_test_zero",      test_mpi_test_zero,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_test_one",       test_mpi_test_one,         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_test_odd",       test_mpi_skip,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_sign",           test_mpi_skip,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_test_probably_prime", test_mpi_skip,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_modn",           test_mpi_skip,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_rshift1_mut",    test_mpi_skip,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_add",            test_mpi_add,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_add_mut",        test_mpi_skip,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_addn",        test_mpi_skip,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_addn_mut",        test_mpi_skip,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_mod_add",        test_mpi_mod_add,          NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_sub",            test_mpi_sub,              srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_sub_mut",        test_mpi_skip,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_subn",        test_mpi_skip,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_subn_mut",        test_mpi_skip,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_mul",            test_mpi_mul,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_mod_mul",        test_mpi_mod_mul,          NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_exp",        test_mpi_skip,          NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_mod_exp",        test_mpi_mod_exp,          NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_mod_sqr_mut",        test_mpi_skip,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_to_dec",         test_mpi_to_dec,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_to_hex",         test_mpi_to_hex,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_to_bytes",       test_mpi_to_bytes_be,      srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
