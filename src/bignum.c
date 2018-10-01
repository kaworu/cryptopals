/*
 * bignum.c
 *
 * Big Number manipulation stuff for cryptopals.com challenges.
 *
 * Currently simply wrapping OpenSSL BIGNUM API.
 */
#include <string.h>
#include <openssl/bn.h>

#include "compat.h"
#include "bignum.h"


struct bignum {
	BIGNUM *bn;
};


struct bignum *
bignum_zero(void)
{
	struct bignum *num = NULL;

	num = malloc(sizeof(struct bignum));
	if (num == NULL)
		return (NULL);

	num->bn = BN_new();
	if (num->bn == NULL) {
		bignum_free(num);
		return (NULL);
	}

	return (num);
}


struct bignum *
bignum_one(void)
{
	struct bignum *one = NULL;

	one = bignum_zero();
	if (one == NULL)
		return (NULL);

	if (BN_one(one->bn) != 1) {
		bignum_free(one);
		return (NULL);
	}

	return (one);
}


struct bignum *
bignum_from_dec(const char *s)
{
	struct bignum *num = NULL;
	int success = 0;

	/* sanity check */
	if (s == NULL)
		goto cleanup;

	num = bignum_zero();
	if (num == NULL)
		goto cleanup;

	if (BN_dec2bn(&num->bn, s) == 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		bignum_free(num);
		num = NULL;
	}
	return (num);
}


struct bignum *
bignum_from_hex(const char *s)
{
	struct bignum *num = NULL;
	int success = 0;

	/* sanity check */
	if (s == NULL)
		goto cleanup;

	num = bignum_zero();
	if (num == NULL)
		goto cleanup;

	if (BN_hex2bn(&num->bn, s) == 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		bignum_free(num);
		num = NULL;
	}
	return (num);
}


struct bignum *
bignum_rand(const struct bignum *limit)
{
	struct bignum *num = NULL;
	int success = 0;

	/* sanity check */
	if (limit == NULL)
		goto cleanup;

	num = bignum_zero();
	if (num == NULL)
		goto cleanup;

	if (BN_rand_range(num->bn, limit->bn) == 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		bignum_free(num);
		num = NULL;
	}
	return (num);
}


struct bignum *
bignum_dup(const struct bignum *n)
{
	struct bignum *cpy = NULL;

	if (n == NULL)
		return (NULL);

	cpy = malloc(sizeof(struct bignum));
	if (cpy == NULL)
		return (NULL);

	cpy->bn = BN_dup(n->bn);
	if (cpy->bn == NULL) {
		bignum_free(cpy);
		return (NULL);
	}

	return (cpy);
}


int
bignum_cmp(const struct bignum *lhs, const struct bignum *rhs)
{
	if (lhs == NULL || rhs == NULL)
		return (INT_MIN);
	return (BN_cmp(lhs->bn, rhs->bn));
}


struct bignum	*bignum_modexp(const struct bignum *base,
		    const struct bignum *exp, const struct bignum *mod)
{
	struct bignum *num = NULL;
	BN_CTX *ctx = NULL;
	int success = 0;

	/* sanity checks */
	if (base == NULL || exp == NULL || mod == NULL)
		goto cleanup;

	num = bignum_zero();
	if (num == NULL)
		goto cleanup;

	ctx = BN_CTX_new();
	if (ctx == NULL)
		goto cleanup;

	if (BN_mod_exp(num->bn, base->bn, exp->bn, mod->bn, ctx) == 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	BN_CTX_free(ctx);
	if (!success) {
		bignum_free(num);
		num = NULL;
	}
	return (num);
}


char *
bignum_to_dec(const struct bignum *num)
{
	if (num == NULL)
		return (NULL);

	char *s = BN_bn2dec(num->bn);
	if (s == NULL)
		return (NULL);
	char *ret = strdup(s);
	OPENSSL_free(s);
	return (ret);
}


char *
bignum_to_hex(const struct bignum *num)
{
	char *s = NULL, *ret = NULL;

	if (num == NULL)
		goto cleanup;

	s = BN_bn2hex(num->bn);
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
bignum_to_bytes_be(const struct bignum *num)
{
	struct bytes *buf = NULL;
	int success = 0;

	if (num == NULL)
		goto cleanup;

	const int n = BN_num_bytes(num->bn);
	if (n < 0)
		goto cleanup;

	buf = bytes_zeroed((size_t)n);
	if (buf == NULL)
		goto cleanup;

	if (BN_bn2bin(num->bn, buf->data) != n)
		goto cleanup;

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
bignum_free(struct bignum *victim)
{
	if (victim != NULL) {
		BN_clear_free(victim->bn);
		freezero(victim, sizeof(struct bignum));
	}
}
