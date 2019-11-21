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


/*
 * Random search for a prime using the Miller–Rabin primality test,
 * see the Handbook of Applied Cryptography §4.44.
 */
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
			switch (mpi_modi(n, d)) {
			case UINT64_MAX:
				goto cleanup;
				/* NOTREACHED */
			case 0: /* d is a divisor of n */
				if (mpi_testi(n, d) == 0) {
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
mpi_addi(const struct mpi *n, const uint64_t i)
{
	struct mpi *r = NULL;
	int success = 0;

	/* sanity check */
	if (n == NULL)
		goto cleanup;

	r = mpi_dup(n);
	if (r == NULL)
		goto cleanup;

	if (mpi_addi_mut(r, i) != 0)
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
mpi_subi(const struct mpi *n, const uint64_t i)
{
	struct mpi *r = NULL;
	int success = 0;

	/* sanity check */
	if (n == NULL)
		goto cleanup;

	r = mpi_dup(n);
	if (r == NULL)
		goto cleanup;

	if (mpi_subi_mut(r, i) != 0)
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
mpi_mul(const struct mpi *a, const struct mpi *b)
{
	struct mpi *r = NULL;
	int success = 0;

	/* sanity checks */
	if (a == NULL || b == NULL)
		goto cleanup;

	r = mpi_dup(a);
	if (r == NULL)
		goto cleanup;

	if (mpi_mul_mut(r, b) != 0)
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
mpi_muli(const struct mpi *n, uint64_t i)
{
	struct mpi *r = NULL;
	int success = 0;

	/* sanity check */
	if (n == NULL)
		goto cleanup;

	r = mpi_dup(n);
	if (r == NULL)
		goto cleanup;

	if (mpi_muli_mut(r, i) != 0)
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
mpi_div(const struct mpi *a, const struct mpi *b)
{
	struct mpi *r = NULL;
	int success = 0;

	/* sanity checks */
	if (a == NULL || b == NULL)
		goto cleanup;

	r = mpi_dup(a);
	if (r == NULL)
		goto cleanup;

	if (mpi_div_mut(r, b) != 0)
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
mpi_divi(const struct mpi *n, uint64_t i)
{
	struct mpi *r = NULL;
	int success = 0;

	/* sanity check */
	if (n == NULL)
		goto cleanup;

	r = mpi_dup(n);
	if (r == NULL)
		goto cleanup;

	if (mpi_divi_mut(r, i) != 0)
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


/*
 * XXX: this function is not implemented over BN_div_word() because, unlike
 * BN_div(), it can't seems to handle negative numbers correctly.
 */
int
mpi_divi_mut(struct mpi *n, uint64_t i)
{
	struct mpi *bigi = NULL;
	int success = 0;

	/* sanity check */
	if (n == NULL)
		return -1;

	bigi = mpi_zero();
	if (mpi_seti(bigi, i) != 0)
		goto cleanup;

	if (mpi_div_mut(n, bigi) != 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	mpi_free(bigi);
	return (success ? 0 : -1);
}


struct mpi *
mpi_sqr(const struct mpi *n)
{
	struct mpi *r = NULL;
	int success = 0;

	/* sanity checks */
	if (n == NULL)
		goto cleanup;

	r = mpi_dup(n);
	if (r == NULL)
		goto cleanup;

	if (mpi_sqr_mut(r) != 0)
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


/*
 * Newton's method implementation based on
 * https://stackoverflow.com/a/35276426/7936137
 */
struct mpi *
mpi_cbrt(const struct mpi *n)
{
	struct mpi *a = NULL, *d = NULL;
	int success = 0;

	if (n == NULL || mpi_sign(n) <= 0)
		goto cleanup;

	/*
	 * Compute our initial guess a as the first power of two that exceeds
	 * the cube root of n.
	 */
	const int nbits = mpi_num_bits(n);
	if (nbits == -1)
		goto cleanup;
	const unsigned shift = (unsigned)nbits / 3 + 1;
	a = mpi_one();
	if (a == NULL)
		goto cleanup;
	if (mpi_lshifti_mut(a, shift) != 0)
		goto cleanup;

	for (;;) {
		struct mpi *a2 = NULL;
		a2 = mpi_sqr(a);
		d = mpi_div(n, a2);
		mpi_free(a2);
		if (d == NULL)
			goto cleanup;
		if (mpi_cmp(a, d) <= 0)
			break;
		if (mpi_muli_mut(a, 2) != 0)
			goto cleanup;
		if (mpi_add_mut(a, d) != 0)
			goto cleanup;
		if (mpi_divi_mut(a, 3) != 0)
			goto cleanup;
		mpi_free(d);
	}

	/* FALLTHROUGH */
	success = 1;
cleanup:
	mpi_free(d);
	if (!success) {
		mpi_free(a);
		a = NULL;
	}
	return a;
}


/*
 * Binary extended gcd algorithm,
 * see the Handbook of Applied Cryptography §14.4.3.
 */
int
mpi_egcd(const struct mpi *cx, const struct mpi *cy, struct mpi **a_p,
		    struct mpi **b_p, struct mpi **v_p)
{
	int success = 0;
	struct mpi *g = NULL, *x = NULL, *y = NULL;
	struct mpi *u = NULL, *v = NULL;
	struct mpi *A = NULL, *B = NULL, *C = NULL, *D = NULL;

	/* sanity checks */
	if (cx == NULL || cy == NULL)
		goto cleanup;

	x = mpi_dup(cx);
	y = mpi_dup(cy);
	g = mpi_one();
	if (x == NULL || y == NULL || g == NULL)
		goto cleanup;

	while (mpi_test_even(x) == 0 && mpi_test_even(y) == 0) {
		/* x = x / 2 */
		if (mpi_rshift1_mut(x) != 0)
			goto cleanup;
		/* y = y / 2 */
		if (mpi_rshift1_mut(y) != 0)
			goto cleanup;
		/* g = 2 * g */
		if (mpi_lshift1_mut(g) != 0)
			goto cleanup;
	}

	u = mpi_dup(x);
	v = mpi_dup(y);
	A = mpi_one();
	B = mpi_zero();
	C = mpi_zero();
	D = mpi_one();
	if (u == NULL || v == NULL)
		goto cleanup;
	if (A == NULL || B == NULL || C == NULL || D == NULL)
		goto cleanup;

	do {
		while (mpi_test_even(u) == 0) {
			/* u = u / 2 */
			if (mpi_rshift1_mut(u) != 0)
				goto cleanup;
			if (mpi_test_even(A) == 0 && mpi_test_even(B) == 0) {
				/* A = A / 2 */
				if (mpi_rshift1_mut(A) != 0)
					goto cleanup;
				/* B = B / 2 */
				if (mpi_rshift1_mut(B) != 0)
					goto cleanup;
			} else {
				/* A = (A + y) / 2 */
				if (mpi_add_mut(A, y) != 0)
					goto cleanup;
				if (mpi_rshift1_mut(A) != 0)
					goto cleanup;
				/* B = (B - x) / 2 */
				if (mpi_sub_mut(B, x) != 0)
					goto cleanup;
				if (mpi_rshift1_mut(B) != 0)
					goto cleanup;
			}
		}
		while (mpi_test_even(v) == 0) {
			/* v = v / 2 */
			if (mpi_rshift1_mut(v) != 0)
				goto cleanup;
			if (mpi_test_even(C) == 0 && mpi_test_even(D) == 0) {
				/* C = C / 2 */
				if (mpi_rshift1_mut(C) != 0)
					goto cleanup;
				/* D = D / 2 */
				if (mpi_rshift1_mut(D) != 0)
					goto cleanup;
			} else {
				/* C = (C + y) / 2 */
				if (mpi_add_mut(C, y) != 0)
					goto cleanup;
				if (mpi_rshift1_mut(C) != 0)
					goto cleanup;
				/* D = (D - x) / 2 */
				if (mpi_sub_mut(D, x) != 0)
					goto cleanup;
				if (mpi_rshift1_mut(D) != 0)
					goto cleanup;
			}
		}
		if (mpi_cmp(u, v) >= 0) {
			/* u = u - v */
			if (mpi_sub_mut(u, v) != 0)
				goto cleanup;
			/* A = A - C */
			if (mpi_sub_mut(A, C) != 0)
				goto cleanup;
			/* B = B - D */
			if (mpi_sub_mut(B, D) != 0)
				goto cleanup;
		} else {
			/* v = v - u */
			if (mpi_sub_mut(v, u) != 0)
				goto cleanup;
			/* C = C - A */
			if (mpi_sub_mut(C, A) != 0)
				goto cleanup;
			/* D = D - B */
			if (mpi_sub_mut(D, B) != 0)
				goto cleanup;
		}
	} while (mpi_test_zero(u) != 0);

	/* v = v * g */
	if (mpi_mul_mut(v, g) != 0)
		goto cleanup;

	success = 1;

	if (a_p != NULL) {
		*a_p = C;
		C = NULL;
	}
	if (b_p != NULL) {
		*b_p = D;
		D = NULL;
	}
	if (v_p != NULL) {
		*v_p = v;
		v = NULL;
	}

	/* FALLTHROUGH */
cleanup:
	mpi_free(D);
	mpi_free(C);
	mpi_free(B);
	mpi_free(A);
	mpi_free(v);
	mpi_free(u);
	mpi_free(g);
	mpi_free(y);
	mpi_free(x);
	return (success ? 0 : -1);
}


/*
 * Multiplicative inverse,
 * see the Handbook of Applied Cryptography §14.64.
 */
struct mpi *
mpi_mod_inv(const struct mpi *a, const struct mpi *m)
{
	struct mpi *inv = NULL, *gcd = NULL;
	int success = 0;

	if (a == NULL || m == NULL)
		goto cleanup;

	/* set x = m, y = a */
	if (mpi_egcd(m, a, NULL, &inv, &gcd) != 0)
		goto cleanup;

	/* if gcd(a, m) != 1 then a is not invertible modulo m */
	if (mpi_test_one(gcd) != 0)
		goto cleanup;

	/* If the inverse is negative, add m to it */
	if (mpi_sign(inv) < 0) {
		if (mpi_add_mut(inv, m) != 0)
			goto cleanup;
	}

	success = 1;
	/* FALLTHROUGH */
cleanup:
	mpi_free(gcd);
	if (!success) {
		mpi_free(inv);
		inv = NULL;
	}
	return inv;
}


/*
 * Miller-Rabin probabilistic primality test,
 * see the Handbook of Applied Cryptography §4.24.
 */
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
	if (mpi_testi(n, 2) == 0)
		goto prime;

	/* even means not prime */
	if (mpi_test_odd(n) != 0)
		goto composite;

	/* write n - 1 = 2**s * r such that r is odd */
	s = mpi_zero();
	r = mpi_subi(n, 1);
	/* s = 0, r = n - 1 */
	do {
		/* s = s + 1 */
		if (mpi_addi_mut(s, 1) != 0)
			goto cleanup;
		/* r = r / 2 */
		if (mpi_rshift1_mut(r) != 0)
			goto cleanup;
	} while (mpi_test_odd(r) != 0);

	/* setup 2, (n - 1), and j for the witness loop */
	two = mpi_from_hex("2");
	n_1 = mpi_subi(n, 1);
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

		if (mpi_seti(j, 1) != 0)
			goto cleanup;
		while (mpi_cmp(j, s) < 0 && mpi_cmp(y, n_1) != 0) {
			if (mpi_mod_sqr_mut(y, n) != 0)
				goto cleanup;
			/* j = j + 1 */
			if (mpi_addi_mut(j, 1) != 0)
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
