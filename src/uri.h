#ifndef URI_H
#define URI_H
/*
 * uri.h
 *
 * URI encoding / decoding functions as per RFC 2396.
 */
#include <stddef.h>


/*
 * Compute the escaped representation's length of a given NUL-terminated string
 * as per RFC 2396 § 2. Note that the computed length does *not* include the
 * terminating NUL of the string that would be returned by uri_escape().
 *
 * The result is stored in len_p if it is not NULL.
 *
 * Returns 0 on success, -1 on error.
 */
int	uri_escape_len(const char *unescaped, size_t *len_p);

/*
 * Create an escaped representation of a given NUL-terminated string as per
 * RFC 2396 § 2.
 *
 * Returns a pointer to a newly allocated NUL-terminated string that should
 * passed to free(). Returns NULL if the given pointer is NULL, or malloc(3)
 * failed.
 */
char	*uri_escape(const char *unescaped);

/*
 * Compute the unescaped representation's length of a given NUL-terminated
 * string as per RFC 2396 § 2. Note that the computed length does *not* include
 * the terminating NUL of the string that would be returned by uri_unescape().
 *
 * The result is stored in len_p if it is not NULL.
 *
 * Returns 0 on success, -1 on error.
 */
int	uri_unescape_len(const char *escaped, size_t *len_p);

/*
 * Create an unescaped representation of a given NUL-terminated string as per
 * RFC 2396 § 2.
 *
 * Returns a pointer to a newly allocated NUL-terminated string that should
 * passed to free(). Returns NULL if the given pointer is NULL, or malloc(3)
 * failed.
 */
char	*uri_unescape(const char *escaped);

#endif /* ndef URI_H */
