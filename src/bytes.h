#ifndef BYTES_H
#define BYTES_H
/*
 * bytes.h
 *
 * Bytes manipulation stuff for cryptopals.com challenges.
 */
#include <stdint.h>
#include <stddef.h>


/*
 * A very simple struct holding a bunch of bytes and the byte count.
 */
struct bytes {
	size_t len;
	uint8_t data[];
};


/*
 * Create a bytes struct of the requested length filled with zero.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(), or NULL if malloc(3) failed.
 */
struct bytes	*bytes_zeroed(size_t len);

/*
 * Create a bytes struct of the requested length filled with the given byte.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(), or NULL if malloc(3) failed.
 */
struct bytes	*bytes_repeated(size_t len, uint8_t byte);

/*
 * Create a bytes struct from a given buffer and its length.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(). Returns NULL if the given buffer pointer is NULL, or malloc(3)
 * failed.
 */
struct bytes	*bytes_from_raw(const void *p, size_t len);

/*
 * Create a bytes struct from a single given byte.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(). Returns NULL if malloc(3) failed.
 */
struct bytes	*bytes_from_single(uint8_t byte);

/*
 * Create a bytes struct from a NUL-terminated string. Note that only strlen(s)
 * bytes are copied; in other words the terminating NUL is not copied.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(). Returns NULL if the given pointer is NULL, or malloc(3) failed.
 */
struct bytes	*bytes_from_str(const char *s);

/*
 * Create a bytes struct from a hex-encoded NUL-terminated string.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(). Returns NULL if the given pointer is NULL, decoding failed, or
 * malloc(3) failed.
 *
 * NOTE: This implementation will reject the encoded data if it contains
 * characters outside the base16 alphabet as per RFC 4648 § 3.3.
 */
struct bytes	*bytes_from_hex(const char *s);

/*
 * Create a bytes struct from a base64-encoded NUL-terminated string.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(). Returns NULL if the given pointer is NULL, decoding failed, or
 * malloc(3) failed.
 */
struct bytes	*bytes_from_base64(const char *s);

/*
 * Create a bytes struct filled with random data. Note that it uses rand(3)
 * *on purpose* and consequently it is *not* very secure.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(), NULL if malloc(3) failed.
 */
struct bytes	*bytes_randomized(size_t len);

/*
 * Create a bytes struct from another bytes struct by duplicating it.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(). Returns NULL if the given pointer is NULL, or malloc(3) failed.
 */
struct bytes	*bytes_dup(const struct bytes *src);

/*
 * Returns 0 if the two given bytes structs are not NULL and have the same
 * length and data, 1 otherwise.
 *
 * NOTE: bytes_bcmp() does *not* run in constant time, see
 * bytes_timingsafe_bcmp().
 */
int	bytes_bcmp(const struct bytes *a, const struct bytes *b);

/*
 * Returns 0 if the two given bytes structs are not NULL and have the same
 * length and data, 1 otherwise.
 *
 * NOTE: Unlike bytes_bcmp(), the running time of bytes_timingsafe_bcmp() is
 * independent of the bytes structs data, and does not return a lexicographic
 * ordering on the data at a and b; it tells only whether they are equal.
 */
int	bytes_timingsafe_bcmp(const struct bytes *a, const struct bytes *b);

/*
 * Create a bytes struct from a slice of another source bytes struct.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(). Returns NULL if the given pointer is NULL, or malloc(3) failed,
 * or if the requested slice is out of bounds.
 */
struct bytes	*bytes_slice(const struct bytes *src,
		    size_t offset, size_t len);

/*
 * Create a bytes struct from several slices of another source bytes struct.
 *
 * Start by ignoring `offset' bytes from the source, then copy it by slice of
 * length `size' ignoring `jump' bytes between each slice.
 *
 * Note that when there are not enough bytes in the source for the last slice,
 * the last slice's length will be smaller than `size'. Thus, the returned
 * buffer length may not be a multiple of the provided `size'.
 *
 * For example
 *     bytes_slices(bytes_from_str("123456e"), 1, 2, 3)
 * should give the same bytes as
 *     bytes_from_str("23e")
 * because "1" is skipped by `offset`, "23" is the first selected slice of size
 * 2, "456" is the jump of size 3 between the first and second slices, and
 * finally "e" is the last incomplete slice of size 1.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(). Returns NULL if the given pointer is NULL, or malloc(3) failed,
 * or offset is out of bound, or size is zero, or the resulting buffer would be
 * empty.
 */
struct bytes	*bytes_slices(const struct bytes *src,
		    size_t offset, size_t size, size_t jump);

/*
 * Compute the Hamming distance between the two given bytes struct.
 *
 * Returns -1 if either argument is NULL or their length doesn't match.
 */
intmax_t	bytes_hamming_distance(const struct bytes *l,
		    const struct bytes *r);

/*
 * Returns a copy of the provided buffer padded to `k' using PCSK#7.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(). Returns NULL if the given pointer is NULL, or k is zero, or
 * malloc(3) failed.
 */
struct bytes	*bytes_pkcs7_padded(const struct bytes *src, uint8_t k);

/*
 * Returns a new buffer that is the concatenation of all the provided buffers
 * (in order). Note that `parts' is not modified.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(). Returns NULL if the given pointer is NULL or malloc(3) failed.
 */
struct bytes	*bytes_joined(struct bytes *const *parts, size_t count);
struct bytes	*bytes_joined_const(const struct bytes *const *parts, size_t count);

/*
 * Copy all the bytes from src into dest starting at a given offset.
 *
 * Returns 0 on succes, -1 if either argument is NULL, dest and src are the
 * same buffer, or if the copy would result in an out-of-bound write.
 */
int	bytes_put(struct bytes *dest, size_t offset, const struct bytes *src);

/*
 * Copy a slice from src into dest starting at a given offset.
 *
 * Returns 0 on succes, -1 if either argument is NULL, dest and src are the
 * same buffer, or if the copy would result in an out-of-bound read or write.
 */
int	bytes_sput(struct bytes *dest, size_t offset,
		    const struct bytes *src, size_t soffset, size_t slen);

/*
 * Returns the NUL-terminated string representation of the given bytes struct.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(). Returns NULL if the given pointer is NULL, or malloc(3) failed.
 */
char	*bytes_to_str(const struct bytes *bytes);

/*
 * Returns the hex representation of the given bytes struct, using uppercase
 * letters.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(). Returns NULL if the given pointer is NULL, or malloc(3) failed.
 */
char	*bytes_to_hex(const struct bytes *bytes);

/*
 * Returns the base64 representation of the given bytes struct.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(). Returns NULL if the given pointer is NULL, or malloc(3) failed.
 */
char	*bytes_to_base64(const struct bytes *bytes);

/*
 * Free the resource associated with the given bytes struct.
 *
 * If not NULL, the data will be zero'd before freed.
 */
void	bytes_free(struct bytes *victim);

#endif /* ndef BYTES_H */
