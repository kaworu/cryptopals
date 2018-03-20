#ifndef BYTES_H
#define BYTES_H
/*
 * bytes.h
 *
 * Bytes manipulation stuff for cryptopals.com challenges.
 */
#include <stdlib.h>
#include <stdint.h>


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
 * Create a bytes struct from another bytes struct by copying it.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(). Returns NULL if the given pointer is NULL, or malloc(3) failed.
 */
struct bytes	*bytes_copy(const struct bytes *src);

/*
 * Compute the Hamming distance between the two given bytes struct.
 *
 * Returns -1 if either argument is NULL or their length doesn't match.
 */
int	bytes_hamming_distance(const struct bytes *a, const struct bytes *b);

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
