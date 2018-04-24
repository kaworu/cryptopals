#ifndef URI_H
#define URI_H
/*
 * uri.h
 *
 * URI encoding / decoding functions as per RFC 2396.
 */
#include <stddef.h>


/*
 * Compute the encoded representation's length of a given NUL-terminated string
 * as per RFC 2396 § 2. Note that the computed length does *not* include the
 * terminating NUL of the string that would be returned by uri_encode().
 *
 * The result is stored in len_p if it is not NULL.
 *
 * Returns 0 on success, -1 on error.
 */
int	uri_encode_len(const char *decoded, size_t *len_p);

/*
 * Create an encoded representation of a given NUL-terminated string as per RFC
 * 2396 § 2.
 *
 * Returns a pointer to a newly allocated NUL-terminated string that should
 * passed to free(). Returns NULL if the given pointer is NULL, or malloc(3)
 * failed.
 */
char	*uri_encode(const char *decoded);

/*
 * Compute the decoded representation's length of a given NUL-terminated string
 * as per RFC 2396 § 2. Note that the computed length does *not* include the
 * terminating NUL of the string that would be returned by uri_decode().
 *
 * The result is stored in len_p if it is not NULL.
 *
 * Returns 0 on success, -1 on error.
 */
int	uri_decode_len(const char *encoded, size_t *len_p);

/*
 * Create an decoded representation of a given NUL-terminated string as per RFC
 * 2396 § 2.
 *
 * Returns a pointer to a newly allocated NUL-terminated string that should
 * passed to free(). Returns NULL if the given pointer is NULL, or malloc(3)
 * failed.
 */
char	*uri_decode(const char *encoded);

#endif /* ndef URI_H */
