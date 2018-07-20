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
	BIGNUM bn;
};


static inline struct bignum *
bignum_alloc(void)
{
	struct bignum *num = NULL;

	num = malloc(sizeof(struct bignum));
	if (num != NULL) {
		BN_init(&num->bn);
	}

	return (num);
}


struct bignum *
bignum_from_dec(const char *s)
{
	struct bignum *num = NULL;
	int success = 0;

	/* sanity check */
	if (s == NULL)
		goto cleanup;

	num = bignum_alloc();
	if (num == NULL)
		goto cleanup;

	BIGNUM *p = &num->bn;
	if (BN_dec2bn(&p, s) == 0)
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

	num = bignum_alloc();
	if (num == NULL)
		goto cleanup;

	BIGNUM *p = &num->bn;
	if (BN_hex2bn(&p, s) == 0)
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

	num = bignum_alloc();
	if (num == NULL)
		goto cleanup;

	if (BN_rand_range(&num->bn, &limit->bn) == 0)
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


int
bignum_cmp(const struct bignum *lhs, const struct bignum *rhs)
{
	if (lhs == NULL || rhs == NULL)
		return (INT_MIN);
	return (BN_cmp(&lhs->bn, &rhs->bn));
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

	num = bignum_alloc();
	if (num == NULL)
		goto cleanup;

	ctx = BN_CTX_new();
	if (ctx == NULL)
		goto cleanup;

	if (BN_mod_exp(&num->bn, &base->bn, &exp->bn, &mod->bn, ctx) == 0)
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

	char *s = BN_bn2dec(&num->bn);
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

	s = BN_bn2hex(&num->bn);
	if (s == NULL)
		goto cleanup;

	ret = calloc(strlen(s) + 1, sizeof(char));
	if (ret == NULL)
		goto cleanup;

	/*
	 * OpenSSL would prefix with zero so that hex number length are always
	 * even, and that not what we want.
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


void
bignum_free(struct bignum *victim)
{
	if (victim != NULL) {
		BN_clear_free(&victim->bn);
		freezero(victim, sizeof(struct bignum));
	}
}
