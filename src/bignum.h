#ifndef BIGNUM_H
#define BIGNUM_H
/*
 * bignum.h
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
struct bignum;


/*
 * Create a bignum struct holding the value 0.
 *
 * Returns a pointer to a newly allocated bignum struct that should passed to
 * bignum_free(), or NULL if malloc(3) failed.
 */
struct bignum	*bignum_zero(void);

/*
 * Create a bignum struct holding the value 1.
 *
 * Returns a pointer to a newly allocated bignum struct that should passed to
 * bignum_free(), or NULL if malloc(3) failed.
 */
struct bignum	*bignum_one(void);

/*
 * Create a bignum struct from a decimal-encoded NUL-terminated string.
 *
 * Returns a pointer to a newly allocated bignum struct that should passed to
 * bignum_free(). Returns NULL if the given pointer is NULL, decoding failed, or
 * malloc(3) failed.
 */
struct bignum	*bignum_from_dec(const char *s);

/*
 * Create a bignum struct from a hex-encoded NUL-terminated string.
 *
 * Returns a pointer to a newly allocated bignum struct that should passed to
 * bignum_free(). Returns NULL if the given pointer is NULL, decoding failed, or
 * malloc(3) failed.
 */
struct bignum	*bignum_from_hex(const char *s);

/*
 * Create a bignum struct from a big-endian bytes buffer.
 *
 * Returns a pointer to a newly allocated bignum struct that should passed to
 * bignum_free(). Returns NULL if the given pointer is NULL, or malloc(3)
 * failed.
 */
struct bignum	*bignum_from_bytes_be(const struct bytes *buf);

/*
 * Returns a cryptographically strong pseudo-random number that is in the range
 * [0,limit[.
 *
 * Returns a pointer to a newly allocated bignum struct that should passed to
 * bignum_free(). Returns NULL if the given pointer is NULL, or malloc(3)
 * failed.
 */
struct bignum	*bignum_rand(const struct bignum *limit);

/*
 * Create a bignum struct from another bignum struct by duplicating it.
 *
 * Returns a pointer to a newly allocated bignum struct that should passed to
 * bignum_free(). Returns NULL if the given pointer is NULL, or malloc(3)
 * failed.
 */
struct bignum	*bignum_dup(const struct bignum *n);

/*
 * Compare two bignum structs.
 *
 * Returns 1, 0, -1 if lhs is found, respectively, to be greater than, equals,
 * or to be lesser than rhs. Returns INT_MIN if either lhs or rhs is NULL.
 */
int	bignum_cmp(const struct bignum *lhs, const struct bignum *rhs);

/*
 * Test if the given bignum struct is zero.
 *
 * Returns 0 if the given bignum struct is zero, 1 otherwise.
 */
int	bignum_is_zero(const struct bignum *n);

/*
 * Test if the given bignum struct is one.
 *
 * Returns 0 if the given bignum struct is one, 1 otherwise.
 */
int	bignum_is_one(const struct bignum *n);

/*
 * Compute and returns the non-negative result of (a + b) % mod.
 *
 * Returns a pointer to a newly allocated bignum struct that should passed to
 * bignum_free(), or NULL on failure.
 */
struct bignum	*bignum_mod_add(const struct bignum *a, const struct bignum *b,
		    const struct bignum *mod);

/*
 * Compute and returns the result of (a - b).
 *
 * Returns a pointer to a newly allocated bignum struct that should passed to
 * bignum_free(). Returns NULL if any argument is NULL, or malloc(3) failed.
 */
struct bignum	*bignum_sub(const struct bignum *a, const struct bignum *b);

/*
 * Compute and returns the result of (n - 1).
 *
 * Returns a pointer to a newly allocated bignum struct that should passed to
 * bignum_free(). Returns NULL if any argument is NULL, or malloc(3) failed.
 */
struct bignum	*bignum_sub_one(const struct bignum *n);

/*
 * Compute and returns the non-negative result of (a * b) % mod.
 *
 * Returns a pointer to a newly allocated bignum struct that should passed to
 * bignum_free(), or NULL on failure.
 */
struct bignum	*bignum_mod_mul(const struct bignum *a, const struct bignum *b,
		    const struct bignum *mod);

/*
 * Compute and returns the result of (base ^ exp) % mod.
 *
 * Returns a pointer to a newly allocated bignum struct that should passed to
 * bignum_free(). Returns NULL if any argument is NULL, or malloc(3) failed.
 */
struct bignum	*bignum_modexp(const struct bignum *base,
		    const struct bignum *exp, const struct bignum *mod);

/*
 * Create a decimal representation of the given bignum struct.
 *
 * Returns a pointer to a newly allocated NUL-terminated string that should
 * passed to free(). Returns NULL if the given pointer is NULL, or malloc(3)
 * failed.
 */
char	*bignum_to_dec(const struct bignum *num);

/*
 * Create a hex representation of the given bignum struct, using uppercase
 * letters.
 *
 * Returns a pointer to a newly allocated NUL-terminated string that should
 * passed to free(). Returns NULL if the given pointer is NULL, or malloc(3)
 * failed.
 */
char	*bignum_to_hex(const struct bignum *num);

/*
 * Create a big-endian bytes buffer representation of the given bignum struct.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(). Returns NULL if the given pointer is NULL, or malloc(3) failed.
 */
struct bytes	*bignum_to_bytes_be(const struct bignum *num);

/*
 * Free the resource associated with the given bignum struct.
 *
 * If not NULL, the data will be zero'd before freed.
 */
void	bignum_free(struct bignum *victim);

#endif /* ndef BIGNUM_H */
