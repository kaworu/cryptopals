/*
 * test_break_dh.c
 */
#include "munit.h"
#include "helpers.h"
#include "dh.h"
#include "break_dh.h"
#include "test_dh.h"


/* Set 5 / Challenge 34 (second part, MITM attack) */
static MunitResult
test_mitm_dh(const MunitParameter *params, void *data)
{
	/* XXX: this test does a little too much, it test both the exchange w/
	   MITM and the echo message */
	struct bignum *p = bignum_from_hex(nist_p_hex);
	struct bignum *g = bignum_from_hex(nist_g_hex);
	if (p == NULL || g == NULL)
		munit_error("bignum_from_hex");

	struct dh *alice = dh_new();
	if (alice == NULL)
		munit_error("dh_new");

	struct dh *mallory = dh_mitm_new(/* bob */dh_new());
	if (mallory == NULL)
		munit_error("dh_mitm_new");

	int ret = alice->exchange(alice, mallory, p, g);
	if (ret != 0)
		munit_error("dh exchange");

	struct bytes *message = bytes_from_str("All we have to decide is what to do with the time that is given us.");
	if (message == NULL)
		munit_error("bytes_from_str");

	ret = alice->challenge(alice, mallory, message);
	munit_assert_int(ret, ==, 0);

	const struct dh_mitm_opaque *ad = mallory->opaque;
	munit_assert_not_null(ad);
	munit_assert_size(ad->count, ==, 1);
	munit_assert_not_null(ad->messages);
	munit_assert_not_null(ad->messages[0]);
	munit_assert_size(ad->messages[0]->len, ==, message->len);
	munit_assert_memory_equal(message->len, ad->messages[0]->data, message->data);

	bytes_free(message);
	mallory->free(mallory);
	alice->free(alice);
	bignum_free(g);
	bignum_free(p);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_break_dh_suite_tests[] = {
	{ "mitm", test_mitm_dh, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
