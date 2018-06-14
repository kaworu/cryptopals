/*
 * break_mt19937.c
 *
 * MT19937 analysis stuff for cryptopals.com challenges.
 */
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "compat.h"
#include "xor.h"
#include "mt19937.h"
#include "break_mt19937.h"


/* undo the MT19937 tempering transform */
static uint32_t	mt19937_untemper(uint32_t x);
/* undo x >> (x & mask) */
static uint32_t	unrshiftmaskxor(uint32_t x, uint32_t rshift, uint32_t mask);
/* undo x << (x & mask) */
static uint32_t	unlshiftmaskxor(uint32_t x, uint32_t lshift, uint32_t mask);


int
mt19937_time_seeder(struct mt19937_generator *gen,
		    uint32_t *n_p, uint32_t *now_p, uint32_t *seed_p)
{
	uint32_t seed, n;
	const uint32_t before_delay = 40 + rand() % (1000 - 40);
	const uint32_t after_delay  = 40 + rand() % (1000 - 40);
	int success = 0;

	/* sanitity check */
	if (gen == NULL)
		goto cleanup;

	/* seed generation */
	if (now_p != NULL) {
		seed = *now_p + before_delay;
	} else {
		sleep(before_delay);
		seed = time(NULL);
		sleep(after_delay);
	}

	/* initialize the generator with the seed */
	if (mt19937_seed(gen, seed) != 0)
		goto cleanup;

	if (n_p != NULL) {
		/* get the first 32 bits of output */
		if (mt19937_next_uint32(gen, &n) != 0)
			goto cleanup;
		*n_p = n;
	}

	if (now_p != NULL)
		*now_p = seed + after_delay;
	if (seed_p != NULL)
		*seed_p = seed;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	return (success ? 0 : -1);
}


int
mt19937_time_seeder_breaker(uint32_t before, uint32_t after, uint32_t generated,
		    uint32_t *seed_p)
{
	struct mt19937_generator *gen = NULL;
	uint32_t seed = 0;
	int found = 0, success = 0;

	gen = mt19937_init(0);
	if (gen == NULL)
		goto cleanup;

	for (seed = before; seed <= after; seed++) {
		uint32_t n = 0;
		if (mt19937_seed(gen, seed) != 0)
			goto cleanup;
		if (mt19937_next_uint32(gen, &n) != 0)
			goto cleanup;
		if (n == generated)
			break;
	}
	found = (seed <= after);

	if (found && seed_p != NULL)
		*seed_p = seed;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	mt19937_free(gen);
	if (!success)
		return (-1);
	return (found ? 0 : 1);
}


struct mt19937_generator *
mt19937_clone(struct mt19937_generator *gen)
{
	struct mt19937_generator *clone = NULL;
	uint32_t state[624] = { 0 };
	int success = 0;

	size_t i;
	for (i = 0; i < (sizeof(state) / sizeof(*state)); i++) {
		uint32_t n = 0;
		if (mt19937_next_uint32(gen, &n) != 0)
			goto cleanup;
		state[i] = mt19937_untemper(n);
	}

	clone = mt19937_from_state(state, i + 1);

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		mt19937_free(clone);
		clone = NULL;
	}
	return (clone);
}


int
mt19937_encryption_breaker(const struct bytes *ciphertext,
		    const struct bytes *known_plaintext, uint16_t *key_p)
{
	uint32_t seed = 0;
	struct bytes *keystream = NULL, *mask = NULL;
	struct mt19937_generator *gen = NULL;
	uint32_t *seq = NULL;
	size_t seqlen = 0;
	int success = 0;

	/* sanitity checks */
	if (ciphertext == NULL || known_plaintext == NULL)
		goto cleanup;
	if (ciphertext->len < known_plaintext->len)
		goto cleanup;

	/* compute the prefix len and the ignore len. The ignore len is
	   basically the prefix len congruent 4 we will try to match 32 bits
	   values from the PRNG */
	const size_t prefixlen = ciphertext->len - known_plaintext->len;
	const size_t ignorelen = prefixlen +
		    (prefixlen % 4 == 0 ? 0 : 4 - (prefixlen % 4));

	/* we need at least 32 bits of ciphertext to match one uin32_t MT19937
	   output */
	if (ciphertext->len + 4 < ignorelen)
		goto cleanup;

	/* To find the keystream from the generator we need to xor the bytes of
	   interest (i.e. thoses after ignorelen) of the ciphertext with the
	   bytes of intereset from the known plaintext */
	keystream = bytes_slice(ciphertext, ignorelen,
		    ciphertext->len - ignorelen);
	if (keystream == NULL)
		goto cleanup;
	mask = bytes_slice(known_plaintext, ignorelen - prefixlen,
		    known_plaintext->len - (ignorelen - prefixlen));
	if (mask == NULL)
		goto cleanup;
	if (bytes_xor(keystream, mask) != 0)
		goto cleanup;

	/* Now that we have a part of the keystream, convert it to 32 bits
	   values so that they will be easy to compare with the PRNG output */
	seqlen = keystream->len / 4;
	seq = calloc(seqlen, sizeof(uint32_t));
	if (seq == NULL)
		goto cleanup;
	for (size_t i = 0; i < seqlen; i++) {
		/* NOTE: LSB first as the encryption does */
		for (size_t qw = 0; qw < 4; qw++) {
			const uint32_t shift = qw * 8;
			const uint32_t byte = keystream->data[4 * i + qw];
			seq[i] |= (byte << shift);
		}
	}

	/* count of word to be ignored (thoses from the prefix) */
	const size_t ignoredwords = ignorelen / 4;
	/* brute-force the 16 bit space since it is practicaly small enough */
	gen = mt19937_init(0);
	for (seed = 0; seed <= UINT16_MAX; seed++) {
		size_t i = 0;
		/* seed the generator with the value from this iteration */
		if (mt19937_seed(gen, seed) != 0)
			goto cleanup;
		/* skip the words from the prefix */
		for (i = 0; i < ignoredwords; i++)
			(void)mt19937_next_uint32(gen, NULL);
		/* compare the PRNG output with our expected sequence */
		for (i = 0; i < seqlen; i++) {
			uint32_t n = 0;
			if (mt19937_next_uint32(gen, &n) != 0)
				goto cleanup;
			if (n != seq[i])
				break;
		}
		if (i == seqlen) {
			/* here the PRNG output for this iteration's seed
			   matches our expected sequence */
			break;
		}
	}
	if (seed > UINT16_MAX)
		goto cleanup;

	if (key_p != NULL)
		*key_p = seed & 0xffff;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	mt19937_free(gen);
	freezero(seq, seqlen);
	bytes_free(mask);
	bytes_free(keystream);
	return (success ? 0 : -1);
}


int
mt19937_token_breaker(const uint32_t *token, size_t tokenlen)
{
	int success = 0;
	int valid = 0;
	const uint32_t now = time(NULL);
	struct mt19937_generator *gen = NULL;

	/* sanity check */
	if (token == NULL)
		goto cleanup;

	gen = mt19937_init(0);
	for (uint32_t seed = now - 60 * 60; seed <= now; seed++) {
		if (mt19937_seed(gen, seed) != 0)
			goto cleanup;
		size_t i = 0;
		for (i = 0; i < tokenlen; i++) {
			uint32_t n = 0;
			if (mt19937_next_uint32(gen, &n) != 0)
				goto cleanup;
			if (token[i] != n)
				break;
		}
		valid = (i == tokenlen);
		if (valid)
			break;
	}

	success = 1;
	/* FALLTHROUGH */
cleanup:
	mt19937_free(gen);
	if (!success)
		return (-1);
	return (valid ? 0 : 1);
}


static uint32_t
mt19937_untemper(uint32_t x)
{
	x = unrshiftmaskxor(x, 18, 0xffffffff);
	x = unlshiftmaskxor(x, 15, 0xefc60000);
	x = unlshiftmaskxor(x,  7, 0x9d2c5680);
	x = unrshiftmaskxor(x, 11, 0xffffffff);
	return (x);
}


static uint32_t
unrshiftmaskxor(uint32_t x, uint32_t rshift, uint32_t mask)
{
	/* naive bit by bit implementation */
	for (uint32_t i = 0; i < (32 - rshift); i++)
		x ^= ((x & (1UL << (31 - i))) >> rshift) & mask;
	return (x);
}


static uint32_t
unlshiftmaskxor(uint32_t x, uint32_t lshift, uint32_t mask)
{
	/* naive bit by bit implementation */
	for (uint32_t i = 0; i < (32 - lshift); i++)
		x ^= ((x & (1UL << i)) << lshift) & mask;
	return (x);
}
