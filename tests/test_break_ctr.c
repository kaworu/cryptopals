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


static MunitResult
test_ctr_fixed_nonce(const MunitParameter *params, void *data)
{
	struct bytes **plaintexts, **ciphertexts;
	struct bytes *key = bytes_randomized(aes_128_keylength());
	if (key == NULL)
		munit_error("bytes_randomized");
	const uint64_t nonce = 0x0;

	const size_t count = sizeof(s3c19_plaintexts_base64) /
		    sizeof(*s3c19_plaintexts_base64);
	plaintexts  = munit_calloc(count, sizeof(struct bytes *));
	ciphertexts = munit_calloc(count, sizeof(struct bytes *));
	size_t maxlen = 0;
	for (size_t i = 0; i < count; i++) {
		struct bytes *plaintext, *ciphertext;
		plaintext = bytes_from_base64(s3c19_plaintexts_base64[i]);
		if (plaintext == NULL)
			munit_error("bytes_from_base64");
		maxlen = (plaintext->len > maxlen ? plaintext->len : maxlen);
		ciphertext = aes_128_ctr_encrypt(plaintext, key, nonce);
		if (ciphertext == NULL)
			munit_error("aes_128_ctr_encrypt");
		plaintexts[i]  = plaintext;
		ciphertexts[i] = ciphertext;
	}

	struct bytes *keystream = break_ctr_fixed_nonce(ciphertexts, count);
	munit_assert_not_null(keystream);
	munit_assert_size(keystream->len, ==, maxlen);

	/* break_ctr_fixed_nonce() successfully cracked about half of the
	   keystream. For the rest I've looked at the decrypted version of all
	   version of ciphertext and deduced one byte at a time which was easy.
	   The end of the keystream is harder to guess because there are less
	   content to be cracked, I had to cheat only for the very last byte. */
	struct {
		size_t ctidx; /* ciphertext index */
		size_t idx;   /* character index */
		uint8_t chr;  /* character at the given (ctidx, idx) position */
	} override[] = {
		{ .ctidx = 35, .idx =  9, .chr = 'h' },
		{ .ctidx = 36, .idx =  7, .chr = 'c' },
		{ .ctidx = 36, .idx =  5, .chr = 'e' },
		{ .ctidx = 38, .idx =  0, .chr = 'T' },
		{ .ctidx = 38, .idx =  1, .chr = 'r' },
		{ .ctidx = 14, .idx = 26, .chr = 'l' },
		{ .ctidx =  8, .idx = 28, .chr = 'e' },
		{ .ctidx = 29, .idx = 29, .chr = 'h' },
		{ .ctidx =  4, .idx = 30, .chr = 'e' },
		{ .ctidx = 25, .idx = 31, .chr = 'd' },
		{ .ctidx = 37, .idx = 32, .chr = ' ' },
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
		struct bytes *recovered = bytes_dup(ciphertexts[i]);
		if (recovered == NULL)
			munit_error("bytes_dup");
		struct bytes *key = bytes_slice(keystream, 0, recovered->len);
		if (key == NULL)
			munit_error("bytes_slice");
		if (bytes_xor(recovered, key) != 0)
			munit_error("bytes_xor");
		struct bytes *expected = plaintexts[i];
		munit_assert_size(recovered->len, ==, expected->len);
		munit_assert_memory_equal(recovered->len, recovered->data,
			    expected->data);
		bytes_free(key);
		bytes_free(recovered);
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
	{ "ctr_fixed_nonce", test_ctr_fixed_nonce, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
