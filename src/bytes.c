/*
 * bytes.c
 *
 * Bytes manipulation stuff for cryptopals.com challenges.
 *
 * About base16 (hex) and base64 encoding see RFC 4648.
 */
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "compat.h"
#include "bytes.h"


/* see https://lemire.me/blog/2016/05/23/the-surprising-cleverness-of-modern-compilers/ */
static inline int
popcnt(uint64_t x)
{
	int v = 0;
	while(x != 0) {
		x &= x - 1;
		v++;
	}
	return v;
}


struct bytes *
bytes_from_str(const char *s)
{
	size_t len;
	struct bytes *ret = NULL;

	if (s == NULL)
		return (NULL);

	len = strlen(s);
	ret = malloc(sizeof(struct bytes) + len * sizeof(uint8_t));
	if (ret == NULL)
		return (NULL);

	ret->len = len;
	(void)memcpy(ret->data, s, len);

	return (ret);
}


struct bytes *
bytes_from_hex(const char *hex)
{
	size_t hexlen, nbytes;
	struct bytes *ret = NULL;
	int success = 0;

	if (hex == NULL)
		goto out;

	/* each byte is encoded as a pair of hex characters, thus if we have an
	   odd count of character we can't decode successfully the string. */
	hexlen = strlen(hex);
	nbytes = hexlen / 2;
	if (nbytes * 2 != hexlen)
		goto out;

	ret = malloc(sizeof(struct bytes) + nbytes * sizeof(uint8_t));
	if (ret == NULL)
		goto out;
	ret->len = nbytes;

	/* decoding loop */
	for (size_t i = 0; i < nbytes; i++) {
		uint8_t msb, lsb; /* 4-bit groups */

		/* first group */
		char c = hex[i * 2];
		if (c >= '0' && c <= '9')
			msb = c - '0';
		else if (c >= 'a' && c <= 'f')
			msb = 10 + c - 'a';
		else if (c >= 'A' && c <= 'F')
			msb = 10 + c - 'A';
		else
			goto out;

		/* second group */
		c = hex[i * 2 + 1];
		if (c >= '0' && c <= '9')
			lsb = c - '0';
		else if (c >= 'a' && c <= 'f')
			lsb = 10 + c - 'a';
		else if (c >= 'A' && c <= 'F')
			lsb = 10 + c - 'A';
		else
			goto out;

		/* construct the current byte using msb and lsb */
		ret->data[i] = (msb << 4) | lsb;
	}

	success = 1;
	/* FALLTHROUGH */
out:
	if (!success) {
		free(ret);
		ret = NULL;
	}
	return (ret);
}


struct bytes *
bytes_copy(const struct bytes *src)
{
	size_t len;
	struct bytes *ret = NULL;

	if (src == NULL)
		return (NULL);

	len = src->len;
	ret = malloc(sizeof(struct bytes) + len * sizeof(uint8_t));
	if (ret == NULL)
		return (NULL);

	ret->len = len;
	(void)memcpy(ret->data, src->data, len);

	return (ret);
}


int
bytes_hamming_distance(const struct bytes *a, const struct bytes *b)
{
	if (a == NULL || b == NULL)
		return (-1);
	if (a->len != b->len)
		return (-1);

	int d = 0;
	for (size_t i = 0; i < a->len; i++)
		d += popcnt(a->data[i] ^ b->data[i]);

	return (d);
}


char *
bytes_to_str(const struct bytes *bytes)
{
	size_t len;
	char *ret = NULL;

	if (bytes == NULL)
		return (NULL);

	len = bytes->len;
	/* one additional character for the terminating NUL. */
	ret = malloc(len + 1);
	if (ret == NULL)
		return (NULL);

	(void)memcpy(ret, bytes->data, len);
	/* NUL-terminated the result string */
	ret[len] = '\0';

	return (ret);
}


char *
bytes_to_hex(const struct bytes *bytes)
{
	/* table of base16 index to character as per § 8 */
	static const char b16table[16] = "0123456789ABCDEF";

	size_t b16len;
	char *ret = NULL;

	if (bytes == NULL)
		return (NULL);

	b16len = bytes->len * 2;
	/* one additional character for the terminating NUL. */
	ret = malloc(b16len + 1);
	if (ret == NULL)
		return (NULL);

	for (size_t i = 0; i < bytes->len; i++) {
		uint8_t byte = bytes->data[i];
		/* pointer to the first character of the current unit */
		char *p = ret + (i * 2);
		p[0] = b16table[byte >> 4];  /* "higher" 4-bit group */
		p[1] = b16table[byte & 0xf]; /* "lower" 4-bit group */
	}

	/* NUL-terminated the result string */
	ret[b16len] = '\0';
	return (ret);
}


char *
bytes_to_base64(const struct bytes *bytes)
{
	/* table of base64 index to character as per § 4 */
	static const char b64table[64] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	/* the base64 padding character */
	static const char b64pad = '=';

	size_t nunit, rbytes, b64len;
	char *ret = NULL;
	size_t i;

	if (bytes == NULL)
		return (NULL);

	/*
	 * base64 encode 6 bits per character. A "unit" is three bytes (i.e. 24
	 * bits) that are represented as four characters in base64. Because our
	 * input may have a count of bytes that is not a multiple of three,
	 * we're left with a potential last "incomplete" unit. Here `nunit' is
	 * the number of "complete" unit we have to encode and `rbytes' the
	 * reminding bytes of the last "incomplete" unit (either zero, one or
	 * two).
	 */
	nunit = bytes->len / 3;
	rbytes = bytes->len % 3;
	b64len = 4 * (nunit + (rbytes ? 1 : 0));

	/* one additional character for the terminating NUL. */
	ret = malloc(b64len + 1);
	if (ret == NULL)
		return (NULL);

	/* encoding loop */
	for (i = 0; i < nunit; i++) {
		/* the three bytes of the current unit */
		uint8_t b0 = bytes->data[i * 3];
		uint8_t b1 = bytes->data[i * 3 + 1];
		uint8_t b2 = bytes->data[i * 3 + 2];
		/* pointer to the first character of the current unit */
		char *p = ret + (i * 4);
		/* first character: leading six bits of the first byte */
		p[0] = b64table[b0 >> 2];
		/* second character: trailing two bits of the first byte
		   followed by the leading four bits of the second byte. */
		p[1] = b64table[((b0 & 0x03) << 4) | (b1 >> 4)];
		/* third character: trailing four bits of the second byte follow
		   by the leading two bits of the third byte. */
		p[2] = b64table[((b1 & 0x0f) << 2) | (b2 >> 6)];
		/* fourth character: trailing six bits of the third byte */
		p[3] = b64table[b2 & 0x3f];
	}

	/* check if we have a final unit to encode with padding */
	if (rbytes > 0) {
		/* pointer to the first character of the final unit */
		char *p = ret + (i * 4);
		if (rbytes == 2) {
			/* this unit is short of exactly one byte. In other
			   words, there are two bytes available for this unit,
			   thus we'll need one padding character. */
			uint8_t b0 = bytes->data[i * 3];
			uint8_t b1 = bytes->data[i * 3 + 1];
			uint8_t b2 = 0;
			p[0] = b64table[b0 >> 2];
			p[1] = b64table[((b0 & 0x03) << 4) | (b1 >> 4)];
			p[2] = b64table[((b1 & 0x0f) << 2) | (b2 >> 6)];
			p[3] = b64pad;
		} else if (rbytes == 1) {
			/* this unit is short of two bytes. In other
			   words, there are only one byte available for this
			   unit, thus we'll need two padding characters. */
			uint8_t b0 = bytes->data[i * 3];
			uint8_t b1 = 0;
			p[0] = b64table[b0 >> 2];
			p[1] = b64table[((b0 & 0x03) << 4) | (b1 >> 4)];
			p[2] = b64pad;
			p[3] = b64pad;
		}
	}

	/* NUL-terminated the result string */
	ret[b64len] = '\0';
	return (ret);
}


void
bytes_free(struct bytes *victim)
{
	size_t len;

	if (victim == NULL)
		return;

	len = (sizeof(struct bytes) + victim->len * sizeof(uint8_t));
	explicit_bzero(victim, len);
	free(victim);
}
