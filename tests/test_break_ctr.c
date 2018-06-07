/*
 * test_break_ctr.c
 */
#include "munit.h"
#include "helpers.h"
#include "break_plaintext.h"
#include "xor.h"
#include "aes.h"
#include "ctr.h"
#include "break_ctr.h"
#include "test_break_ctr.h"


/* Set 3 / Challenge 19 */
static MunitResult
test_ctr_fixed_nonce_1(const MunitParameter *params, void *data)
{
	struct bytes **plaintexts, **ciphertexts;
	struct bytes *key = bytes_randomized(aes_128_keylength());
	if (key == NULL)
		munit_error("bytes_randomized");
	const uint64_t nonce = 0x0;

	const size_t count = sizeof(s3c19_plaintexts_base64) /
		    sizeof(*s3c19_plaintexts_base64);

	/* decode the plaintexts and compute the longest length */
	plaintexts = munit_calloc(count, sizeof(struct bytes *));
	size_t maxlen = 0;
	for (size_t i = 0; i < count; i++) {
		struct bytes *plaintext;
		plaintext = bytes_from_base64(s3c19_plaintexts_base64[i]);
		if (plaintext == NULL)
			munit_error("bytes_from_base64");
		maxlen = (plaintext->len > maxlen ? plaintext->len : maxlen);
		plaintexts[i] = plaintext;
	}

	/* encrypt the plaintexts to generate the ciphertexts */
	ciphertexts = munit_calloc(count, sizeof(struct bytes *));
	for (size_t i = 0; i < count; i++) {
		struct bytes *ciphertext;
		ciphertext = aes_128_ctr_encrypt(plaintexts[i], key, nonce);
		if (ciphertext == NULL)
			munit_error("aes_128_ctr_encrypt");
		ciphertexts[i] = ciphertext;
	}

	struct bytes *keystream = break_ctr_fixed_nonce(ciphertexts, count);
	munit_assert_not_null(keystream);
	munit_assert_size(keystream->len, ==, maxlen);

	/*
	 * break_ctr_fixed_nonce() successfully cracked most of the keystream.
	 * For the rest I've looked at the guessed plaintexts and deduced one
	 * byte at a time which was easy. The end of the keystream is harder to
	 * guess because there are less content to be cracked, I had to cheat
	 * only for the very last byte.
	 */
	struct {
		size_t ctidx; /* ciphertext index */
		size_t idx;   /* character index */
		uint8_t chr;  /* character at the given (ctidx, idx) position */
	} override[] = {
		{ .ctidx =  0, .idx =  0, .chr = 'I' }, /* capitalize */
		{ .ctidx =  4, .idx = 33, .chr = 'e' },
		{ .ctidx =  4, .idx = 34, .chr = 'a' },
		{ .ctidx =  4, .idx = 35, .chr = 'd' },
		{ .ctidx = 37, .idx = 36, .chr = 'n' },
		{ .ctidx = 37, .idx = 37, .chr = ',' }, /* cheated this one */
	};

	/* "fix" the keystream using the manual override values */
	for (size_t i = 0; i < sizeof(override) / sizeof(*override); i++) {
		size_t ctidx = override[i].ctidx;
		size_t idx   = override[i].idx;
		uint8_t chr  = override[i].chr;
		keystream->data[idx] = ciphertexts[ctidx]->data[idx] ^ chr;
	}

	/* XOR each ciphertext with the keystream and verify its value against
	   the known plaintext */
	for (size_t i = 0; i < count; i++) {
		struct bytes *recovered = ciphertexts[i];
		struct bytes *mask = bytes_slice(keystream, 0, recovered->len);
		if (mask == NULL)
			munit_error("bytes_slice");
		if (bytes_xor(recovered, mask) != 0)
			munit_error("bytes_xor");
		struct bytes *expected = plaintexts[i];
		munit_assert_size(recovered->len, ==, expected->len);
		munit_assert_memory_equal(recovered->len, recovered->data,
			    expected->data);
		bytes_free(mask);
	}

	bytes_free(keystream);
	for (size_t i = 0; i < count; i++)
		bytes_free(ciphertexts[i]);
	free(ciphertexts);
	for (size_t i = 0; i < count; i++)
		bytes_free(plaintexts[i]);
	free(plaintexts);
	bytes_free(key);

	return (MUNIT_OK);
}


/* Set 3 / Challenge 20 */
static MunitResult
test_ctr_fixed_nonce_2(const MunitParameter *params, void *data)
{
	struct bytes **plaintexts, **ciphertexts;
	struct bytes *key = bytes_randomized(aes_128_keylength());
	if (key == NULL)
		munit_error("bytes_randomized");
	const uint64_t nonce = 0x0;

	const size_t count = sizeof(s3c20_plaintexts_base64) /
		    sizeof(*s3c20_plaintexts_base64);

	/* decode the plaintexts and compute the shortest length */
	plaintexts = munit_calloc(count, sizeof(struct bytes *));
	size_t minlen = 0;
	for (size_t i = 0; i < count; i++) {
		struct bytes *plaintext;
		plaintext = bytes_from_base64(s3c20_plaintexts_base64[i]);
		if (plaintext == NULL)
			munit_error("bytes_from_base64");
		minlen = (i == 0 || plaintext->len < minlen ?
			    plaintext->len : minlen);
		plaintexts[i] = plaintext;
	}

	/* encrypt the plaintexts to generate the ciphertexts */
	ciphertexts = munit_calloc(count, sizeof(struct bytes *));
	for (size_t i = 0; i < count; i++) {
		struct bytes *plaintext, *ciphertext;
		/* trim the plaintext to minlen */
		plaintext = bytes_slice(plaintexts[i], 0, minlen);
		if (plaintext == NULL)
			munit_error("bytes_slice");
		bytes_free(plaintexts[i]);
		plaintexts[i] = plaintext;
		/* encrypt the trimmed version of the plaintext */
		ciphertext = aes_128_ctr_encrypt(plaintext, key, nonce);
		if (ciphertext == NULL)
			munit_error("aes_128_ctr_encrypt");
		ciphertexts[i] = ciphertext;
	}

	struct bytes *keystream = break_ctr_fixed_nonce(ciphertexts, count);
	munit_assert_not_null(keystream);
	munit_assert_size(keystream->len, ==, minlen);

	/* XOR each ciphertext with the keystream and verify its value against
	   the known plaintext */
	for (size_t i = 0; i < count; i++) {
		struct bytes *recovered = ciphertexts[i];
		if (bytes_xor(recovered, keystream) != 0)
			munit_error("bytes_xor");
		const struct bytes *expected = plaintexts[i];
		munit_assert_size(recovered->len, ==, expected->len);
		munit_assert_memory_equal(recovered->len, recovered->data,
			    expected->data);
	}

	bytes_free(keystream);
	for (size_t i = 0; i < count; i++)
		bytes_free(ciphertexts[i]);
	free(ciphertexts);
	for (size_t i = 0; i < count; i++)
		bytes_free(plaintexts[i]);
	free(plaintexts);
	bytes_free(key);

	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_break_ctr_suite_tests[] = {
	{ "ctr_fixed_nonce-1", test_ctr_fixed_nonce_1, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "ctr_fixed_nonce-2", test_ctr_fixed_nonce_2, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
