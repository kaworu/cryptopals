/*
 * mpi.c
 *
 * Big Number manipulation stuff for cryptopals.com challenges.
 *
 * The mpi functions are split between mpi0.c and mpi.c (this file).  This is
 * done that way in order to be able to have our own mpi implementation some day
 * (i.e. not using OpenSSL BN). Only mpi0.c would need to be rewritten.
 *
 * Here belongs advanced functions like EGCD, Miller-Rabin test etc. They are
 * using primitive functions from mpi0.c.
 */
#include "compat.h"
#include "mpi.h"


/* Miller–Rabin primality test */
static int	miller_rabin_test(const struct mpi *n, size_t t);


struct mpi *
mpi_rand_range(const struct mpi *min, const struct mpi *max)
{
	struct mpi *delta = NULL, *n = NULL;
	int success = 0;

	/* sanity check */
	if (min == NULL || max == NULL)
		goto cleanup;
	if (mpi_cmp(min, max) == 1)
		goto cleanup;

	delta = mpi_sub(max, min);
	if (delta == NULL)
		goto cleanup;

	/* 0 <= n < (max - min) */
	n = mpi_rand_range_from_zero_to(delta);
	if (n == NULL)
		goto cleanup;

	/* n += min */
	if (mpi_add_mut(n, min) != 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	mpi_free(delta);
	if (!success) {
		mpi_free(n);
		n = NULL;
	}
	return (n);
}


struct mpi *
mpi_rand_range_from_one_to(const struct mpi *limit)
{
	struct mpi *one = NULL, *n = NULL;
	int success = 0;

	/* sanity check */
	if (limit == NULL)
		goto cleanup;

	one = mpi_one();
	n = mpi_rand_range(one, limit);
	if (n == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	mpi_free(one);
	if (!success) {
		mpi_free(n);
		n = NULL;
	}
	return (n);
}


struct mpi *
mpi_probable_prime(const size_t bits)
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

	struct mpi *n = NULL;
	int success = 0;

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
retry:
		mpi_free(n);
		n = mpi_rand_odd_top2(bits);
		if (n == NULL)
			goto cleanup;

		/* trial division stage */
		for (size_t i = 0; i < (sizeof(primes) / sizeof(*primes)); i++) {
			const unsigned int d = primes[i];
			switch (mpi_modn(n, d)) {
			case UINT64_MAX:
				goto cleanup;
				/* NOTREACHED */
			case 0: /* d is a divisor of n */
				if (mpi_testn(n, d) == 0) {
					/* n is actually the prime number */
					success = 1;
					goto cleanup;
					/* NOTREACHED */
				} else {
					goto retry;
				}
			}
		}

		switch (miller_rabin_test(n, t)) {
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
		mpi_free(n);
		n = NULL;
	}
	return n;
}

int
mpi_test_even(const struct mpi *n)
{
	if (n == NULL)
		return 1;

	const int is_even = (mpi_test_odd(n) != 0);
	return (is_even ? 0 : 1);
}


struct mpi *
mpi_add(const struct mpi *a, const struct mpi *b)
{
	struct mpi *r = NULL;
	int success = 0;

	/* sanity checks */
	if (a == NULL || b == NULL)
		goto cleanup;

	r = mpi_dup(a);
	if (r == NULL)
		goto cleanup;

	if (mpi_add_mut(r, b) != 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		mpi_free(r);
		r = NULL;
	}
	return r;
}


struct mpi *
mpi_addn(const struct mpi *a, const uint64_t n)
{
	struct mpi *r = NULL;
	int success = 0;

	/* sanity check */
	if (a == NULL)
		goto cleanup;

	r = mpi_dup(a);
	if (r == NULL)
		goto cleanup;

	if (mpi_addn_mut(r, n) != 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		mpi_free(r);
		r = NULL;
	}
	return r;
}


struct mpi *
mpi_sub(const struct mpi *a, const struct mpi *b)
{
	struct mpi *r = NULL;
	int success = 0;

	/* sanity checks */
	if (a == NULL || b == NULL)
		goto cleanup;

	r = mpi_dup(a);
	if (r == NULL)
		goto cleanup;

	if (mpi_sub_mut(r, b) != 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		mpi_free(r);
		r = NULL;
	}
	return r;
}


struct mpi *
mpi_subn(const struct mpi *a, const uint64_t n)
{
	struct mpi *r = NULL;
	int success = 0;

	/* sanity check */
	if (a == NULL)
		goto cleanup;

	r = mpi_dup(a);
	if (r == NULL)
		goto cleanup;

	if (mpi_subn_mut(r, n) != 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		mpi_free(r);
		r = NULL;
	}
	return r;
}


static int
miller_rabin_test(const struct mpi *n, size_t t)
{
	struct mpi *s = NULL, *r = NULL;
	struct mpi *two = NULL, *n_1 = NULL;
	struct mpi *j = NULL, *y = NULL;
	int success = 0, prime = 0;

	/* sanity checks */
	if (n == NULL)
		goto cleanup;
	if (mpi_sign(n) <= 0)
		goto cleanup;

	/* 1 and 2 */
	if (mpi_test_one(n) == 0)
		goto composite;
	if (mpi_testn(n, 2) == 0)
		goto prime;

	/* even means not prime */
	if (mpi_test_odd(n) != 0)
		goto composite;

	/* write n - 1 = 2**s * r such that r is odd */
	s = mpi_zero();
	r = mpi_subn(n, 1);
	/* s = 0, r = n - 1 */
	do {
		/* s = s + 1 */
		if (mpi_addn_mut(s, 1) != 0)
			goto cleanup;
		/* r = r / 2 */
		if (mpi_rshift1_mut(r) != 0)
			goto cleanup;
	} while (mpi_test_odd(r) != 0);

	/* setup 2, (n - 1), and j for the witness loop */
	two = mpi_from_hex("2");
	n_1 = mpi_subn(n, 1);
	j   = mpi_zero();
	while (t--) {
		/* Choose a random integer a such as 2 <= a < n - 1 */
		struct mpi *a = mpi_rand_range(two, n_1);
		/* y = a**r % n */
		y = mpi_mod_exp(a, r, n);
		mpi_free(a);
		if (y == NULL)
			goto cleanup;

		if (mpi_test_one(y) == 0 || mpi_cmp(y, n_1) == 0)
			goto next_round;

		if (mpi_setn(j, 1) != 0)
			goto cleanup;
		while (mpi_cmp(j, s) < 0 && mpi_cmp(y, n_1) != 0) {
			if (mpi_mod_sqr_mut(y, n) != 0)
				goto cleanup;
			/* j = j + 1 */
			if (mpi_addn_mut(j, 1) != 0)
				goto cleanup;
		}

		if (mpi_cmp(y, n_1) != 0)
			goto composite;
		/* FALLTHROUGH */
next_round:
		mpi_free(y);
		y = NULL;
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
	mpi_free(y);
	mpi_free(j);
	mpi_free(n_1);
	mpi_free(two);
	mpi_free(r);
	mpi_free(s);
	if (!success)
		return -1;
	else
		return (prime ? 0 : 1);
}
