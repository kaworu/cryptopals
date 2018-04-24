/*
 * uri.c
 *
 * URI encoding / decoding functions as per RFC 2396.
 */
#include <stdint.h>
#include <stdlib.h>

#include "compat.h"
#include "uri.h"


/*
 * Returns 1 if the given character should be encoded, 0 otherwise.
 *
 * see https://tools.ietf.org/html/rfc2396#section-2.2
 */
static inline int
must_be_encoded(char c)
{
	/* alpha characters don't need to be encoded */
	if ((c >= 'a' && c <= 'z') ||(c >= 'A' && c <= 'Z'))
		return (0);

	/* digits don't need to be encoded */
	if (c >= '0' && c <= '9')
		return (0);

	/* mark characters don't need to be encoded */
	switch (c) {
	case '-':  /* FALLTHROUGH */
	case '_':  /* FALLTHROUGH */
	case '.':  /* FALLTHROUGH */
	case '!':  /* FALLTHROUGH */
	case '~':  /* FALLTHROUGH */
	case '*':  /* FALLTHROUGH */
	case '\'': /* FALLTHROUGH */
	case '(':  /* FALLTHROUGH */
	case ')':
		return (0);
	}

	return (1);
}


int
uri_encode_len(const char *decoded, size_t *len_p)
{
	size_t len = 0;
	int success = 0;

	/* sanity check */
	if (decoded == NULL)
		goto cleanup;

	for (const char *p = decoded; *p != '\0'; p++)
		len += (must_be_encoded(*p) ? 3 : 1);

	if (len_p != NULL)
		*len_p = len;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	return (success ? 0 : -1);
}


char *
uri_encode(const char *decoded)
{
	static const char b16table[16] = "0123456789ABCDEF";
	size_t len = 0;
	char *encoded = NULL;
	int success = 0;

	/* sanity check */
	if (decoded == NULL)
		goto cleanup;

	if (uri_encode_len(decoded, &len) != 0)
		goto cleanup;
	encoded = calloc(len + 1, sizeof(char));
	if (encoded == NULL)
		goto cleanup;

	char *d = encoded;
	for (const char *p = decoded; *p != '\0'; p++) {
		if (!must_be_encoded(*p)) {
			*d++ = *p;
		} else {
			const uint8_t byte = (uint8_t)*p;
			*d++ = '%';
			*d++ = b16table[byte >> 4];
			*d++ = b16table[byte & 0xf];
		}
	}

	success = (d == encoded + len);
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		freezero(encoded, len);
		encoded = NULL;
	}
	return (encoded);
}


int
uri_decode_len(const char *encoded, size_t *len_p)
{
	size_t len = 0;
	int success = 0;

	/* sanity check */
	if (encoded == NULL)
		goto cleanup;

	for (const char *p = encoded; *p != '\0'; p++) {
		if (*p == '%') {
			int is_digit, is_hex_alpha;
			p++;
			is_digit = (*p >= '0' && *p <= '9');
			is_hex_alpha = (*p >= 'a' && *p <= 'f') ||
				    (*p >= 'A' && *p <= 'F');
			if (!(is_digit || is_hex_alpha))
				goto cleanup;
			p++;
			is_digit = (*p >= '0' && *p <= '9');
			is_hex_alpha = (*p >= 'a' && *p <= 'f') ||
				    (*p >= 'A' && *p <= 'F');
			if (!(is_digit || is_hex_alpha))
				goto cleanup;
		} else if (must_be_encoded(*p)) {
			goto cleanup;
		}
		len += 1;
	}

	if (len_p != NULL)
		*len_p = len;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	return (success ? 0 : -1);
}


char *
uri_decode(const char *encoded)
{
	size_t len = 0;
	char *decoded = NULL;
	int success = 0;

	/* sanity check */
	if (encoded == NULL)
		goto cleanup;

	if (uri_decode_len(encoded, &len) != 0)
		goto cleanup;
	decoded = calloc(len + 1, sizeof(char));
	if (decoded == NULL)
		goto cleanup;

	char *d = decoded;
	for (const char *p = encoded; *p != '\0'; p++) {
		if (*p != '%') {
			*d++ = *p;
		} else {
			uint8_t hi = 0, lo = 0;
			p++;
			if (*p >= '0' && *p <= '9')
				hi = *p - '0';
			else if (*p >= 'a' && *p <= 'f')
				hi = 10 + *p - 'a';
			else if (*p >= 'A' && *p <= 'F')
				hi = 10 + *p - 'A';
			else
				goto cleanup;
			p++;
			if (*p >= '0' && *p <= '9')
				lo = *p - '0';
			else if (*p >= 'a' && *p <= 'f')
				lo = 10 + *p - 'a';
			else if (*p >= 'A' && *p <= 'F')
				lo = 10 + *p - 'A';
			else
				goto cleanup;
			*d++ = (char)((hi << 4) | lo);
		}
	}

	success = (d == decoded + len);
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		freezero(decoded, len);
		decoded = NULL;
	}
	return (decoded);
}
