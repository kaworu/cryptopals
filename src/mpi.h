#ifndef BIGNUM_H
#define BIGNUM_H
/*
 * mpi.h
 *
 * Big Number manipulation stuff for cryptopals.com challenges.
 *
 * Currently simply wrapping OpenSSL BIGNUM API.
 */
#include "bytes.h"
#include <limits.h>


/*
 * Represent numbers of arbitrary precision.
 */
struct mpi;


/*
 * Create a mpi struct holding the value 0.
 *
 * Returns a pointer to a newly allocated mpi struct that should passed to
 * mpi_free(), or NULL if malloc(3) failed.
 */
struct mpi	*mpi_zero(void);

/*
 * Create a mpi struct holding the value 1.
 *
 * Returns a pointer to a newly allocated mpi struct that should passed to
 * mpi_free(), or NULL if malloc(3) failed.
 */
struct mpi	*mpi_one(void);

/*
 * Create a mpi struct from a decimal-encoded NUL-terminated string.
 *
 * Returns a pointer to a newly allocated mpi struct that should passed to
 * mpi_free(). Returns NULL if the given pointer is NULL, decoding failed, or
 * malloc(3) failed.
 */
struct mpi	*mpi_from_dec(const char *s);

/*
 * Create a mpi struct from a hex-encoded NUL-terminated string.
 *
 * Returns a pointer to a newly allocated mpi struct that should passed to
 * mpi_free(). Returns NULL if the given pointer is NULL, decoding failed, or
 * malloc(3) failed.
 */
struct mpi	*mpi_from_hex(const char *s);

/*
 * Create a mpi struct from a big-endian bytes buffer.
 *
 * Returns a pointer to a newly allocated mpi struct that should passed to
 * mpi_free(). Returns NULL if the given pointer is NULL, or malloc(3) failed.
 */
struct mpi	*mpi_from_bytes_be(const struct bytes *buf);

/*
 * Returns a cryptographically strong pseudo-random number n such as
 * min <= n < max.
 *
 * Returns a pointer to a newly allocated mpi struct that should passed to
 * mpi_free(). Returns NULL if min or max is NULL, max < min, or on failure.
 */
struct mpi	*mpi_rand_range(const struct mpi *min, const struct mpi *max);

/*
 * Returns a cryptographically strong pseudo-random number n such as
 * 0 <= n < limit.
 *
 * Returns a pointer to a newly allocated mpi struct that should passed to
 * mpi_free(). Returns NULL if the given pointer is NULL, or on failure.
 */
struct mpi	*mpi_rand_range_from_zero_to(const struct mpi *limit);

/*
 * Returns a cryptographically strong pseudo-random number n such as
 * 1 <= n < limit.
 *
 * Returns a pointer to a newly allocated mpi struct that should passed to
 * mpi_free(). Returns NULL if the given pointer is NULL, or on failure.
 */
struct mpi	*mpi_rand_range_from_one_to(const struct mpi *limit);

/*
 * Returns a cryptographically strong pseudo-random odd number of the given
 * numbers of bits. The the two most significant bits of the number will be set
 * to 1, so that the product of two such random numbers will always have 2*bits
 * length.
 *
 * XXX: OpenSSL represent bits as int and we require the first two bits to be 1.
 * Thus, bits must satisfy 2 <= bits <= INT_MAX.
 *
 * Returns a pointer to a newly allocated mpi struct that should passed to
 * mpi_free(). Returns NULL if bits is too small, too long, or on failure.
 */
struct mpi	*mpi_rand_odd_top2(const size_t bits);

/*
 * Create a mpi struct from another mpi struct by duplicating it.
 *
 * Returns a pointer to a newly allocated mpi struct that should passed to
 * mpi_free(). Returns NULL if the given pointer is NULL, or malloc(3) failed.
 */
struct mpi	*mpi_dup(const struct mpi *n);

/*
 * Set a to n.
 *
 * Returns 0 on success, -1 on failure.
 */
int	mpi_setn(struct mpi *a, const uint64_t n);

/*
 * Returns a probable prime number of the given length in bits.
 *
 * Random search for a prime using the Miller–Rabin primality test, see the
 * Handbook of Applied Cryptography §4.44.
 *
 * XXX: OpenSSL represent bits as int and we require the first two bits to be 1.
 * Thus, bits must satisfy 2 <= bits <= INT_MAX.
 *
 * Returns a pointer to a newly allocated mpi struct that should passed to
 * mpi_free(). Returns NULL if bits is too small, too long, or on failure.
 */
struct mpi	*mpi_probable_prime(const size_t bits);

/*
 * Compare two mpis.
 *
 * Returns 1, 0, -1 if a is found, respectively, to be greater than, equals, or
 * to be lesser than b. Returns INT_MIN if either a or b is NULL.
 */
int	mpi_cmp(const struct mpi *a, const struct mpi *b);

/*
 * Compare a to n.
 *
 * Returns 0 if they are equals, 1 otherwise (including when n is NULL).
 */
int	mpi_testn(const struct mpi *a, const uint64_t n);

/*
 * Test if n is zero. Equivalent to mpi_testn(n, 0).
 *
 * Returns 0 if n is zero, 1 otherwise.
 */
int	mpi_test_zero(const struct mpi *n);

/*
 * Test if n is one. Equivalent to mpi_testn(n, 1).
 *
 * Returns 0 if n is one, 1 otherwise.
 */
int	mpi_test_one(const struct mpi *n);

/*
 * Test if n is odd.
 *
 * Returns 0 if n is odd, 1 (even or NULL).
 */
int	mpi_test_odd(const struct mpi *n);

/*
 * Test if n is even.
 *
 * Returns 0 if n is even, 1 (odd or NULL).
 */
int	mpi_test_even(const struct mpi *n);

/*
 * Test if n is negative.
 *
 * Returns -1 if n is negative, 0 if n is NULL or zero, 1 otherwise.
 */
int	mpi_sign(const struct mpi *n);

/*
 * Test if n is probably prime.
 *
 * Returns 0 if n is probably prime, 1 if it is composite, -1 on failure
 * (including when n = 0 and n is negative).
 */
int	mpi_test_probably_prime(const struct mpi *n);

/*
 * Compute and returns the result a % n.
 *
 * Returns UINT64_MAX if a is NULL, a % n otherwise.
 */
uint64_t	mpi_modn(const struct mpi *a, const uint64_t n);

/*
 * left shift n from one bit.
 *
 * Returns 0 on success, -1 on failure.
 */
int	mpi_lshift1_mut(struct mpi *n);

/*
 * right shift n from one bit.
 *
 * Returns 0 on success, -1 on failure.
 */
int	mpi_rshift1_mut(struct mpi *n);

/*
 * Compute and returns the result of a + b.
 *
 * Returns a pointer to a newly allocated mpi struct that should passed to
 * mpi_free(), or NULL on failure.
 */
struct mpi	*mpi_add(const struct mpi *a, const struct mpi *b);

/*
 * Add b to a.
 *
 * Returns 0 on success, -1 on failure.
 */
int	mpi_add_mut(struct mpi *a, const struct mpi *b);

/*
 * Compute and returns the result of a + n.
 *
 * Returns a pointer to a newly allocated mpi struct that should passed to
 * mpi_free(), or NULL on failure.
 */
struct mpi	*mpi_addn(const struct mpi *a, const uint64_t n);

/*
 * Add n to a.
 *
 * Returns 0 on success, -1 on failure.
 */
int	mpi_addn_mut(struct mpi *a, const uint64_t n);

/*
 * Compute and returns the non-negative result of (a + b) % mod.
 *
 * Returns a pointer to a newly allocated mpi struct that should passed to
 * mpi_free(), or NULL on failure.
 */
struct mpi	*mpi_mod_add(const struct mpi *a, const struct mpi *b,
		    const struct mpi *mod);

/*
 * Compute and returns the result of a - b.
 *
 * Returns a pointer to a newly allocated mpi struct that should passed to
 * mpi_free(). Returns NULL if any argument is NULL, or malloc(3) failed.
 */
struct mpi	*mpi_sub(const struct mpi *a, const struct mpi *b);

/*
 * Subtract b to a.
 *
 * Returns 0 on success, -1 on failure.
 */
int	mpi_sub_mut(struct mpi *a, const struct mpi *b);

/*
 * Compute and returns the result of a - n.
 *
 * Returns a pointer to a newly allocated mpi struct that should passed to
 * mpi_free(), or NULL on failure.
 */
struct mpi	*mpi_subn(const struct mpi *a, const uint64_t n);

/*
 * Subtract n to a.
 *
 * Returns 0 on success, -1 on failure.
 */
int	mpi_subn_mut(struct mpi *a, const uint64_t n);

/*
 * Compute and returns the result of a * b.
 *
 * Returns a pointer to a newly allocated mpi struct that should passed to
 * mpi_free(), or NULL on failure.
 */
struct mpi	*mpi_mul(const struct mpi *a, const struct mpi *b);

/*
 * Multiply a by b.
 *
 * Returns 0 on success, -1 on failure.
 */
int	mpi_mul_mut(struct mpi *a, const struct mpi *b);

/*
 * Compute and returns the non-negative result of (a * b) % mod.
 *
 * Returns a pointer to a newly allocated mpi struct that should passed to
 * mpi_free(), or NULL on failure.
 */
struct mpi	*mpi_mod_mul(const struct mpi *a, const struct mpi *b,
		    const struct mpi *mod);

/*
 * Compute and returns the result of base ** exp.
 *
 * Returns a pointer to a newly allocated mpi struct that should passed to
 * mpi_free(), or NULL on failure.
 */
struct mpi	*mpi_exp(const struct mpi *base, const struct mpi *exp);

/*
 * Compute and returns the result of (base ** exp) % mod.
 *
 * Returns a pointer to a newly allocated mpi struct that should passed to
 * mpi_free(). Returns NULL if any argument is NULL, or malloc(3) failed.
 */
struct mpi	*mpi_mod_exp(const struct mpi *base,
		    const struct mpi *exp, const struct mpi *mod);

/*
 * n = (n ** 2) % mod
 *
 * Returns 0 on success, -1 on failure.
 */
int	mpi_mod_sqr_mut(struct mpi *n, const struct mpi *mod);

/*
 * Create a decimal representation of n.
 *
 * Returns a pointer to a newly allocated NUL-terminated string that should
 * passed to free(). Returns NULL if the given pointer is NULL, or malloc(3)
 * failed.
 */
char	*mpi_to_dec(const struct mpi *n);

/*
 * Create a hex representation of n using uppercase letters.
 *
 * Returns a pointer to a newly allocated NUL-terminated string that should
 * passed to free(). Returns NULL if the given pointer is NULL, or malloc(3)
 * failed.
 */
char	*mpi_to_hex(const struct mpi *n);

/*
 * Create a big-endian bytes buffer representation of n.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(). Returns NULL if the given pointer is NULL, or malloc(3) failed.
 */
struct bytes	*mpi_to_bytes_be(const struct mpi *n);

/*
 * Free the resource associated with the given mpi struct.
 *
 * If not NULL, the data will be zero'd before freed.
 */
void	mpi_free(struct mpi *n);

#endif /* ndef BIGNUM_H */
