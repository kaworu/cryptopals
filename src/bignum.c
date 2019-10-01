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


/* Miller–Rabin primality test */
static int	miller_rabin_test(const BIGNUM *n, size_t t);


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

	if (BN_one(one->bn) == 0) {
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
bignum_from_bytes_be(const struct bytes *buf)
{
	struct bignum *num = NULL;
	unsigned char *s = NULL;
	size_t slen = 0;
	int success = 0;

	/* sanity check */
	if (buf == NULL)
		goto cleanup;

	num = bignum_zero();
	if (num == NULL)
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

	if (BN_bin2bn(s, slen, num->bn) != num->bn)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	freezero(s, slen);
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
bignum_probable_prime(const size_t bits)
{
	/*
	 * primes table used for the trial division stage.
	 * By using the bound B = 256 80% of candidate will be discarded before
	 * the more costly Miller-Rabin test.
	 *
	 * See the Handbook of Applied Cryptography §4.4.1
	 */
	static const unsigned int primes[] = {
		  2,   3,   5,  7,   11,  13,  17,  19,  23,  29,  31,  37,  41,
		 43,  47,  53,  59,  61,  67,  71,  73,  79,  83,  89,  97, 101,
		103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
		173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239,
		241, 251
	};

	struct bignum *num = NULL;
	int success = 0;

	/* sanity check */
	if (bits < 2 || bits > INT_MAX)
		goto cleanup;

	num = bignum_zero();
	if (num == NULL)
		goto cleanup;

	/*
	 * Pick t such as the error probability is <= 2**-80,
	 * see the Handbook of Applied Cryptography table 4.4.
	 */
	const size_t t = bits >= 1300 ?  2 : \
			 bits >=  850 ?  3 : \
			 bits >=  650 ?  4 : \
			 bits >=  550 ?  5 : \
			 bits >=  450 ?  6 : \
			 bits >=  400 ?  7 : \
			 bits >=  350 ?  8 : \
			 bits >=  300 ?  9 : \
			 bits >=  250 ? 12 : \
			 bits >=  200 ? 15 : \
			 bits >=  150 ? 18 : \
			 /* bits >= 100 */ 27;
	while (!success) {
		/*
		 * if top is 1, the two most significant bits of the number will
		 * be set to 1, so that the product of two such random numbers
		 * will always have 2*bits length.
		 */
		const int top = 1;
		/* If bottom is true, the number will be odd. */
		const int bottom = 1;
		if (BN_rand(num->bn, (int)bits, top, bottom) == 0)
			goto cleanup;

		/* trial division stage */
		int pass = 1;
		for (size_t i = 0; i < (sizeof(primes) / sizeof(*primes)); i++) {
			const unsigned int d = primes[i];
			if (BN_mod_word(num->bn, d) == 0) {
				if (BN_is_word(num->bn, d)) {
					/* num is actually the prime number */
					success = 1;
					goto cleanup;
				} else {
					/* d is a divisor of num */
					pass = 0;
					break;
				}
			}
		}
		if (!pass)
			continue;

		switch (miller_rabin_test(num->bn, t)) {
		case -1:
			goto cleanup;
		case 0: /* probably prime */
			success = 1;
			break;
		default:
			continue;
		}
	}

	/* FALLTHROUGH */
cleanup:
	if (!success) {
		bignum_free(num);
		num = NULL;
	}
	return num;
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


int
bignum_is_zero(const struct bignum *n)
{
	if (n == NULL)
		return (1);
	const int is_zero = (BN_is_zero(n->bn) == 1);
	return (is_zero ? 0 : 1);
}


int
bignum_is_one(const struct bignum *n)
{
	if (n == NULL)
		return (1);
	const int is_one = (BN_is_one(n->bn) == 1);
	return (is_one ? 0 : 1);
}


int
bignum_is_probably_prime(const struct bignum *n)
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


struct bignum *
bignum_add(const struct bignum *a, const struct bignum *b)
{
	struct bignum *result = NULL;
	int success = 0;

	/* sanity checks */
	if (a == NULL || b == NULL)
		goto cleanup;

	result = bignum_zero();
	if (result == NULL)
		goto cleanup;

	if (BN_add(result->bn, a->bn, b->bn) == 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		bignum_free(result);
		result = NULL;
	}
	return (result);
}


struct bignum *
bignum_mod_add(const struct bignum *a, const struct bignum *b,
		    const struct bignum *mod)
{
	struct bignum *result = NULL;
	BN_CTX *ctx = NULL;
	int success = 0;

	/* sanity checks */
	if (a == NULL || b == NULL || mod == NULL)
		goto cleanup;

	ctx = BN_CTX_new();
	if (ctx == NULL)
		goto cleanup;

	result = bignum_zero();
	if (result == NULL)
		goto cleanup;

	if (BN_mod_add(result->bn, a->bn, b->bn, mod->bn, ctx) == 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	BN_CTX_free(ctx);
	if (!success) {
		bignum_free(result);
		result = NULL;
	}
	return (result);
}


struct bignum *
bignum_sub(const struct bignum *a, const struct bignum *b)
{
	struct bignum *result = NULL;
	int success = 0;

	/* sanity checks */
	if (a == NULL || b == NULL)
		goto cleanup;

	result = bignum_zero();
	if (result == NULL)
		goto cleanup;

	if (BN_sub(result->bn, a->bn, b->bn) == 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		bignum_free(result);
		result = NULL;
	}
	return (result);
}


struct bignum *
bignum_sub_one(const struct bignum *n)
{
	struct bignum *result = NULL;
	int success = 0;

	/* sanity check */
	if (n == NULL)
		goto cleanup;

	result = bignum_dup(n);
	if (result == NULL)
		goto cleanup;

	if (BN_sub_word(result->bn, 1) == 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		bignum_free(result);
		result = NULL;
	}
	return (result);
}


struct bignum *
bignum_mul(const struct bignum *a, const struct bignum *b)
{
	struct bignum *result = NULL;
	BN_CTX *ctx = NULL;
	int success = 0;

	/* sanity checks */
	if (a == NULL || b == NULL)
		goto cleanup;

	ctx = BN_CTX_new();
	if (ctx == NULL)
		goto cleanup;

	result = bignum_zero();
	if (result == NULL)
		goto cleanup;

	if (BN_mul(result->bn, a->bn, b->bn, ctx) == 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	BN_CTX_free(ctx);
	if (!success) {
		bignum_free(result);
		result = NULL;
	}
	return (result);
}


struct bignum *
bignum_mod_mul(const struct bignum *a, const struct bignum *b,
		    const struct bignum *mod)
{
	struct bignum *result = NULL;
	BN_CTX *ctx = NULL;
	int success = 0;

	/* sanity checks */
	if (a == NULL || b == NULL || mod == NULL)
		goto cleanup;

	ctx = BN_CTX_new();
	if (ctx == NULL)
		goto cleanup;

	result = bignum_zero();
	if (result == NULL)
		goto cleanup;

	if (BN_mod_mul(result->bn, a->bn, b->bn, mod->bn, ctx) == 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	BN_CTX_free(ctx);
	if (!success) {
		bignum_free(result);
		result = NULL;
	}
	return (result);
}


struct bignum *
bignum_mod_exp(const struct bignum *base, const struct bignum *exp,
		    const struct bignum *mod)
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

	/* XXX: OpenSSL will produce an empty buffer for zero instead of one 0x0
	   value. So we check explicitely for zero. */
	if (bignum_is_zero(num) == 0) {
		buf = bytes_zeroed(1);
	} else {
		const int n = BN_num_bytes(num->bn);
		if (n < 0)
			goto cleanup;

		buf = bytes_zeroed((size_t)n);
		if (buf == NULL)
			goto cleanup;

		if (BN_bn2bin(num->bn, buf->data) != n)
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
bignum_free(struct bignum *num)
{
	if (num == NULL)
		return;

	BN_clear_free(num->bn);
	freezero(num, sizeof(struct bignum));
}


static int
miller_rabin_test(const BIGNUM *n, size_t t)
{
	BIGNUM *z = NULL, *s = NULL, *r = NULL;
	BIGNUM *n_1 = NULL, *n_3 = NULL;
	BN_CTX *ctx = NULL;
	int success = 0, prime = 0;

	z = BN_new();
	/* sanity checks */
	if (n == NULL || z == NULL)
		goto cleanup;
	if (BN_cmp(n, z) <= 0)
		goto cleanup;

	/* 1 and 2 */
	if (BN_is_one(n))
		goto composite;
	if (BN_is_word(n, 2))
		goto prime;

	/* even means not prime */
	if (!BN_is_odd(n))
		goto composite;

	/* write n - 1 = 2**s * r such that r is odd */
	s = BN_new();
	if (s == NULL)
		goto cleanup;
	r = BN_dup(n);
	if (r == NULL)
		goto cleanup;
	if (BN_sub_word(r, 1) == 0)
		goto cleanup;
	/* s = 0; r = n - 1 */
	do {
		/* s = s + 1 */
		if (BN_add_word(s, 1) == 0)
			goto cleanup;
		/* r = r / 2 */
		if (BN_rshift1(r, r) == 0)
			goto cleanup;
	} while (!BN_is_odd(r));

	/* setup a context, n - 1, n - 3 for the witness loop */
	ctx = BN_CTX_new();
	if (ctx == NULL)
		goto cleanup;
	n_1 = BN_dup(n);
	if (n_1 == NULL)
		goto cleanup;
	if (BN_sub_word(n_1, 1) == 0)
		goto cleanup;
	n_3 = BN_dup(n);
	if (n_3 == NULL)
		goto cleanup;
	if (BN_sub_word(n_3, 3) == 0)
		goto cleanup;

	while (t--) {
		BIGNUM *a = NULL, *y = NULL, *j = NULL;
		int loop_success = 0, loop_prime = 0;

		/*
		 * Choose a random integer a, 2 <= a <= n - 2.
		 *
		 * Note that BN_rand_range() generate a number in the range
		 * [0, limit[. Thus, we ask for a number in the range [0, n - 3[
		 * and add 2 to it.
		 */
		a = BN_new();
		if (a == NULL)
			goto loop_cleanup;
		if (BN_rand_range(a, n_3) == 0)
			goto loop_cleanup;
		if (BN_add_word(a, 2) == 0)
			goto loop_cleanup;

		/* y = a**r % n */
		y = BN_new();
		if (y == NULL)
			goto loop_cleanup;
		if (BN_mod_exp(y, a, r, n, ctx) == 0)
			goto loop_cleanup;

		if (BN_is_one(y) || BN_cmp(y, n_1) == 0)
			goto loop_prime;

		j = BN_dup(BN_value_one());
		if (j == NULL)
			goto loop_cleanup;
		while (BN_cmp(j, s) < 0 && BN_cmp(y, n_1) != 0) {
			BIGNUM *y2 = BN_new();
			if (y2 == NULL)
				goto loop_cleanup;
			/* y = y**2 % n */
			if (BN_mod_sqr(y2, y, n, ctx) == 0) {
				BN_clear_free(y2);
				goto loop_cleanup;
			}
			if (BN_copy(/* to */y, /* from */y2) != y) {
				BN_clear_free(y2);
				goto loop_cleanup;
			}
			BN_clear_free(y2);
			/* j = j + 1 */
			if (BN_add_word(j, 1) == 0)
				goto loop_cleanup;
		}

		if (BN_cmp(y, n_1) != 0)
			goto loop_composite;
		/* FALLTHROUGH */
loop_prime:
		loop_success = 1;
		loop_prime = 1;
		goto loop_cleanup;
		/* NOTREACHED */
loop_composite:
		loop_success = 1;
		loop_prime = 0;
		/* FALLTHROUGH */
loop_cleanup:
		BN_clear_free(j);
		BN_clear_free(y);
		BN_clear_free(a);
		if (!loop_success)
			goto cleanup;
		else if (!loop_prime)
			goto composite;
	}

	/* FALLTHROUGH */
prime:
	success = 1;
	prime = 1;
	goto cleanup;
	/* NOTREACHED */
composite:
	success = 1;
	prime = 0;
	/* FALLTHROUGH */
cleanup:
	BN_clear_free(n_3);
	BN_clear_free(n_1);
	BN_CTX_free(ctx);
	BN_clear_free(r);
	BN_clear_free(s);
	BN_clear_free(z);
	if (!success)
		return -1;
	else
		return (prime ? 0 : 1);
}
