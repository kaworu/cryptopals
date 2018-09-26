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
 * Returns a cryptographically strong pseudo-random number that is in the range
 * [0,limit[.
 *
 * Returns a pointer to a newly allocated bignum struct that should passed to
 * bignum_free(). Returns NULL if the given pointer is NULL, or malloc(3)
 * failed.
 */
struct bignum	*bignum_rand(const struct bignum *limit);

/*
 * Compare two bignum structs.
 *
 * Returns 1, 0, -1 if lhs is found, respectively, to be greater than, equals,
 * or to be lesser than rhs. Returns INT_MIN if either lhs or rhs is NULL.
 */
int	bignum_cmp(const struct bignum *lhs, const struct bignum *rhs);

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
