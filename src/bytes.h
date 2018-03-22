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
 * Create a bytes struct from a NUL-terminated string.
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
 * Create a bytes struct from another bytes struct by duplicating it.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(). Returns NULL if the given pointer is NULL, or malloc(3) failed.
 */
struct bytes	*bytes_dup(const struct bytes *src);

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
intmax_t	bytes_hamming_distance(const struct bytes *, const struct bytes *);

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
