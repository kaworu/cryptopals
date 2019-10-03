/*
 * mpi0.c
 *
 * Big Number stuff for cryptopals.com challenges.
 *
 * The mpi functions are split between mpi0.c (this file) and mpi.c.  This is
 * done that way in order to be able to have our own mpi implementation some day
 * (i.e. not using OpenSSL BN). Only mpi0.c would need to be rewritten.
 *
 * Function from this file are currently simply wrapping OpenSSL BIGNUM API.
 * Here belongs only the OpenSSL BN aware primitive function. Advanced functions
 * like EGCD, Miller-Rabin test etc. belongs to mpi.c.
 */
#include <string.h>
#include <openssl/bn.h>

#include "compat.h"
#include "mpi.h"


struct mpi {
	BIGNUM *bn;
};


struct mpi *
mpi_zero(void)
{
	struct mpi *zero = NULL;

	zero = malloc(sizeof(struct mpi));
	if (zero == NULL)
		return (NULL);

	zero->bn = BN_new();
	if (zero->bn == NULL) {
		mpi_free(zero);
		return (NULL);
	}

	return zero;
}


struct mpi *
mpi_one(void)
{
	struct mpi *one = NULL;

	one = mpi_zero();
	if (one == NULL)
		return (NULL);

	if (BN_one(one->bn) == 0) {
		mpi_free(one);
		return (NULL);
	}

	return (one);
}


struct mpi *
mpi_from_dec(const char *s)
{
	struct mpi *n = NULL;
	int success = 0;

	/* sanity check */
	if (s == NULL)
		goto cleanup;

	n = mpi_zero();
	if (n == NULL)
		goto cleanup;

	if (BN_dec2bn(&n->bn, s) == 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		mpi_free(n);
		n = NULL;
	}
	return (n);
}


struct mpi *
mpi_from_hex(const char *s)
{
	struct mpi *n = NULL;
	int success = 0;

	/* sanity check */
	if (s == NULL)
		goto cleanup;

	n = mpi_zero();
	if (n == NULL)
		goto cleanup;

	if (BN_hex2bn(&n->bn, s) == 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		mpi_free(n);
		n = NULL;
	}
	return (n);
}


struct mpi *
mpi_from_bytes_be(const struct bytes *buf)
{
	struct mpi *n = NULL;
	unsigned char *s = NULL;
	size_t slen = 0;
	int success = 0;

	/* sanity check */
	if (buf == NULL)
		goto cleanup;

	n = mpi_zero();
	if (n == NULL)
		goto cleanup;

	/*
	 * NOTE: BN_bin2bn() expect `const unsigned char *`
	 */
	slen = buf->len;
	s = malloc(slen);
	if (s == NULL)
		goto cleanup;
	for (size_t i = 0; i < slen; i++)
		s[i] = buf->data[i];

	if (BN_bin2bn(s, slen, n->bn) != n->bn)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	freezero(s, slen);
	if (!success) {
		mpi_free(n);
		n = NULL;
	}
	return (n);
}


struct mpi *
mpi_rand_range_from_zero_to(const struct mpi *limit)
{
	struct mpi *n = NULL;
	int success = 0;

	/* sanity check */
	if (limit == NULL)
		goto cleanup;

	n = mpi_zero();
	if (n == NULL)
		goto cleanup;

	if (BN_rand_range(n->bn, limit->bn) == 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		mpi_free(n);
		n = NULL;
	}
	return (n);
}


struct mpi *
mpi_rand_odd_top2(const size_t bits)
{
	int success = 0;
	struct mpi *n = NULL;

	/* sanity check */
	if (bits < 2 || bits > INT_MAX)
		goto cleanup;

	n = mpi_zero();
	if (n == NULL)
		goto cleanup;

	/*
	 * if top is 1, the two most significant bits of the number will
	 * be set to 1, so that the product of two such random numbers
	 * will always have 2*bits length.
	 */
	const int top = 1;
	/* If bottom is true, the number will be odd. */
	const int bottom = 1;
	if (BN_rand(n->bn, (int)bits, top, bottom) == 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		mpi_free(n);
		n = NULL;
	}
	return n;
}


struct mpi *
mpi_dup(const struct mpi *n)
{
	struct mpi *cpy = NULL;

	if (n == NULL)
		return (NULL);

	cpy = malloc(sizeof(struct mpi));
	if (cpy == NULL)
		return (NULL);

	cpy->bn = BN_dup(n->bn);
	if (cpy->bn == NULL) {
		mpi_free(cpy);
		return (NULL);
	}

	return (cpy);
}


int
mpi_setn(struct mpi *a, const uint64_t n)
{
	/* sanity check */
	if (a == NULL)
		return -1;

	const int success = BN_set_word(a->bn, n);
	return (success ? 0 : -1);
}


int
mpi_cmp(const struct mpi *a, const struct mpi *b)
{
	/* sanity checks */
	if (a == NULL || b == NULL)
		return (INT_MIN);

	return (BN_cmp(a->bn, b->bn));
}


int
mpi_testn(const struct mpi *a, const uint64_t n)
{
	if (a == NULL)
		return 1;

	const int is_word = BN_is_word(a->bn, n);
	return (is_word ? 0 : 1);
}


int
mpi_test_zero(const struct mpi *n)
{
	if (n == NULL)
		return 1;

	const int is_zero = BN_is_zero(n->bn);
	return (is_zero ? 0 : 1);
}


int
mpi_test_one(const struct mpi *n)
{
	if (n == NULL)
		return 1;

	const int is_one = BN_is_one(n->bn);
	return (is_one ? 0 : 1);
}


int
mpi_test_odd(const struct mpi *n)
{
	if (n == NULL)
		return 1;

	const int odd = BN_is_odd(n->bn);
	return (odd ? 0 : 1);
}


int
mpi_sign(const struct mpi *n)
{
	if (n == NULL || mpi_test_zero(n) == 0)
		return 0;
	else if (BN_is_negative(n->bn))
		return -1;
	else
		return 1;
}


int
mpi_test_probably_prime(const struct mpi *n)
{
	BN_CTX *ctx = NULL;
	int success = 0, prime = 0;

	/* sanity check */
	if (n == NULL)
		goto cleanup;

	ctx = BN_CTX_new();
	if (ctx == NULL)
		goto cleanup;

	prime = BN_is_prime_ex(n->bn, BN_prime_checks, ctx, /* callback */NULL);
	success = 1;
	/* FALLTHROUGH */
cleanup:
	BN_CTX_free(ctx);
	if (!success)
		return -1;
	else
		return (prime ? 0 : 1);
}


uint64_t
mpi_modn(const struct mpi *a, const uint64_t n)
{
	/* sanity check */
	if (a == NULL)
		return UINT64_MAX;

	return BN_mod_word(a->bn, n);
}


int
mpi_rshift1_mut(struct mpi *n)
{
	/* sanity check */
	if (n == NULL)
		return -1;

	const int success = BN_rshift1(n->bn, n->bn);
	return (success ? 0 : -1);
}


int
mpi_add_mut(struct mpi *a, const struct mpi *b)
{
	/* sanity checks */
	if (a == NULL || b == NULL)
		return -1;

	const int success = BN_add(a->bn, a->bn, b->bn);
	return (success ? 0 : -1);
}


int
mpi_addn_mut(struct mpi *a, uint64_t n)
{
	/* sanity check */
	if (a == NULL)
		return -1;

	const int success = BN_add_word(a->bn, n);
	return (success ? 0 : -1);
}


struct mpi *
mpi_mod_add(const struct mpi *a, const struct mpi *b, const struct mpi *mod)
{
	struct mpi *result = NULL;
	BN_CTX *ctx = NULL;
	int success = 0;

	/* sanity checks */
	if (a == NULL || b == NULL || mod == NULL)
		goto cleanup;

	ctx = BN_CTX_new();
	if (ctx == NULL)
		goto cleanup;

	result = mpi_zero();
	if (result == NULL)
		goto cleanup;

	if (BN_mod_add(result->bn, a->bn, b->bn, mod->bn, ctx) == 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	BN_CTX_free(ctx);
	if (!success) {
		mpi_free(result);
		result = NULL;
	}
	return (result);
}


int
mpi_sub_mut(struct mpi *a, const struct mpi *b)
{
	/* sanity checks */
	if (a == NULL || b == NULL)
		return -1;

	const int success = BN_sub(a->bn, a->bn, b->bn);
	return (success ? 0 : -1);
}


int
mpi_subn_mut(struct mpi *a, uint64_t n)
{
	/* sanity check */
	if (a == NULL)
		return -1;

	const int success = BN_sub_word(a->bn, n);
	return (success ? 0 : -1);
}


struct mpi *
mpi_mul(const struct mpi *a, const struct mpi *b)
{
	struct mpi *result = NULL;
	BN_CTX *ctx = NULL;
	int success = 0;

	/* sanity checks */
	if (a == NULL || b == NULL)
		goto cleanup;

	ctx = BN_CTX_new();
	if (ctx == NULL)
		goto cleanup;

	result = mpi_zero();
	if (result == NULL)
		goto cleanup;

	if (BN_mul(result->bn, a->bn, b->bn, ctx) == 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	BN_CTX_free(ctx);
	if (!success) {
		mpi_free(result);
		result = NULL;
	}
	return (result);
}


struct mpi *
mpi_mod_mul(const struct mpi *a, const struct mpi *b, const struct mpi *mod)
{
	struct mpi *result = NULL;
	BN_CTX *ctx = NULL;
	int success = 0;

	/* sanity checks */
	if (a == NULL || b == NULL || mod == NULL)
		goto cleanup;

	ctx = BN_CTX_new();
	if (ctx == NULL)
		goto cleanup;

	result = mpi_zero();
	if (result == NULL)
		goto cleanup;

	if (BN_mod_mul(result->bn, a->bn, b->bn, mod->bn, ctx) == 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	BN_CTX_free(ctx);
	if (!success) {
		mpi_free(result);
		result = NULL;
	}
	return (result);
}


struct mpi *
mpi_mod_exp(const struct mpi *base, const struct mpi *exp,
		    const struct mpi *mod)
{
	struct mpi *n = NULL;
	BN_CTX *ctx = NULL;
	int success = 0;

	/* sanity checks */
	if (base == NULL || exp == NULL || mod == NULL)
		goto cleanup;

	n = mpi_zero();
	if (n == NULL)
		goto cleanup;

	ctx = BN_CTX_new();
	if (ctx == NULL)
		goto cleanup;

	if (BN_mod_exp(n->bn, base->bn, exp->bn, mod->bn, ctx) == 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	BN_CTX_free(ctx);
	if (!success) {
		mpi_free(n);
		n = NULL;
	}
	return (n);
}


int
mpi_mod_sqr_mut(struct mpi *n, const struct mpi *mod)
{
	BN_CTX *ctx = NULL;
	int success = 0;

	/* sanity checks */
	if (n == NULL || mod == NULL)
		goto cleanup;

	ctx = BN_CTX_new();
	if (ctx == NULL)
		goto cleanup;

	if (BN_mod_sqr(n->bn, n->bn, mod->bn, ctx) == 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	BN_CTX_free(ctx);
	return (success ? 0 : -1);
}


char *
mpi_to_dec(const struct mpi *n)
{
	if (n == NULL)
		return (NULL);

	char *s = BN_bn2dec(n->bn);
	if (s == NULL)
		return (NULL);
	char *ret = strdup(s);
	OPENSSL_free(s);
	return (ret);
}


char *
mpi_to_hex(const struct mpi *n)
{
	char *s = NULL, *ret = NULL;

	if (n == NULL)
		goto cleanup;

	s = BN_bn2hex(n->bn);
	if (s == NULL)
		goto cleanup;

	ret = calloc(strlen(s) + 1, sizeof(char));
	if (ret == NULL)
		goto cleanup;

	/*
	 * OpenSSL would prefix with zero so that hex number length are always
	 * even, and that isn't what we want.
	 */
	char *p = s, *r = ret;
	/* skip over the leading minus, if any */
	if (*p == '-')
		*r++ = *p++;
	/* skip over the leading zero if the result is not zero itself */
	while (*p == '0' && p[1] != '\0')
		p++;
	while (*p != '\0')
		*r++ = *p++;

cleanup:
	OPENSSL_free(s);
	return (ret);
}


struct bytes *
mpi_to_bytes_be(const struct mpi *n)
{
	struct bytes *buf = NULL;
	int success = 0;

	if (n == NULL)
		goto cleanup;

	/* XXX: OpenSSL will produce an empty buffer for zero instead of one 0x0
	   value. So we check explicitely for zero. */
	if (mpi_test_zero(n) == 0) {
		buf = bytes_zeroed(1);
	} else {
		const int i = BN_num_bytes(n->bn);
		if (i < 0)
			goto cleanup;

		buf = bytes_zeroed((size_t)i);
		if (buf == NULL)
			goto cleanup;

		if (BN_bn2bin(n->bn, buf->data) != i)
			goto cleanup;
	}

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		bytes_free(buf);
		buf = NULL;
	}
	return (buf);
}


void
mpi_free(struct mpi *n)
{
	if (n == NULL)
		return;

	BN_clear_free(n->bn);
	freezero(n, sizeof(struct mpi));
}
