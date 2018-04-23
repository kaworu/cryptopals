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
 * Returns 1 if the given character should be escaped, 0 otherwise.
 *
 * see https://tools.ietf.org/html/rfc2396#section-2.2
 */
static inline int
must_be_escaped(char c)
{
	/* alpha characters don't need to be escaped */
	if ((c >= 'a' && c <= 'z') ||(c >= 'A' && c <= 'Z'))
		return (0);

	/* digits don't need to be escaped */
	if (c >= '0' && c <= '9')
		return (0);

	/* mark characters don't need to be escaped */
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
uri_escape_len(const char *unescaped, size_t *len_p)
{
	size_t len = 0;
	int success = 0;

	/* sanity check */
	if (unescaped == NULL)
		goto cleanup;

	for (const char *p = unescaped; *p != '\0'; p++)
		len += (must_be_escaped(*p) ? 3 : 1);

	if (len_p != NULL)
		*len_p = len;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	return (success ? 0 : -1);
}


char *
uri_escape(const char *unescaped)
{
	static const char b16table[16] = "0123456789ABCDEF";
	size_t len = 0;
	char *escaped = NULL;
	int success = 0;

	/* sanity check */
	if (unescaped == NULL)
		goto cleanup;

	if (uri_escape_len(unescaped, &len) != 0)
		goto cleanup;
	escaped = calloc(len + 1, sizeof(char));
	if (escaped == NULL)
		goto cleanup;

	char *d = escaped;
	for (const char *p = unescaped; *p != '\0'; p++) {
		if (!must_be_escaped(*p)) {
			*d++ = *p;
		} else {
			const uint8_t byte = (uint8_t)*p;
			*d++ = '%';
			*d++ = b16table[byte >> 4];
			*d++ = b16table[byte & 0xf];
		}
	}

	success = (d == escaped + len);
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		freezero(escaped, len);
		escaped = NULL;
	}
	return (escaped);
}


int
uri_unescape_len(const char *escaped, size_t *len_p)
{
	size_t len = 0;
	int success = 0;

	/* sanity check */
	if (escaped == NULL)
		goto cleanup;

	for (const char *p = escaped; *p != '\0'; p++) {
		int is_num, is_alpha;
		len += 1;
		if (*p != '%')
			continue;
		p++;
		is_num   = (*p >= '0' && *p <= '9');
		is_alpha = (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F');
		if (!(is_num || is_alpha))
			goto cleanup;
		p++;
		is_num   = (*p >= '0' && *p <= '9');
		is_alpha = (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F');
		if (!(is_num || is_alpha))
			goto cleanup;
	}

	if (len_p != NULL)
		*len_p = len;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	return (success ? 0 : -1);
}


char *
uri_unescape(const char *escaped)
{
	size_t len = 0;
	char *unescaped = NULL;
	int success = 0;

	/* sanity check */
	if (escaped == NULL)
		goto cleanup;

	if (uri_unescape_len(escaped, &len) != 0)
		goto cleanup;
	unescaped = calloc(len + 1, sizeof(char));
	if (unescaped == NULL)
		goto cleanup;

	char *d = unescaped;
	for (const char *p = escaped; *p != '\0'; p++) {
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

	success = (d == unescaped + len);
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		freezero(unescaped, len);
		unescaped = NULL;
	}
	return (unescaped);
}
