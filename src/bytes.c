/*
 * bytes.c
 *
 * Bytes manipulation stuff for cryptopals.com challenges.
 *
 * About base16 (aka hex) and base64 encoding see RFC 4648.
 */
#include <stdlib.h>
#include <string.h>

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


/*
 * Decode a single base64 character into a byte. Note that only the trailing
 * 6-bit are relevant. Returns UINT8_MAX if the given character is out not in
 * the base64 alphabet.
 */
static inline uint8_t
b64decode(char c)
{
	if (c >= 'A' && c <= 'Z')
		return (c - 'A');
	if (c >= 'a' && c <= 'z')
		return (26 + c - 'a');
	if (c >= '0' && c <= '9')
		return (52 + c - '0');
	if (c == '+')
		return (62);
	if (c == '/')
		return (63);

	/* meh */
	return (UINT8_MAX);
}


struct bytes *
bytes_from_raw(const void *p, size_t len)
{
	struct bytes *buf = NULL;

	/* sanity check */
	if (p == NULL)
		return (NULL);

	buf = malloc(sizeof(struct bytes) + len * sizeof(uint8_t));
	if (buf == NULL)
		return (NULL);

	buf->len = len;
	(void)memcpy(buf->data, p, len);

	return (buf);
}


struct bytes *
bytes_from_single(uint8_t byte)
{
	return (bytes_from_raw(&byte, 1));
}


struct bytes *
bytes_from_str(const char *s)
{
	/* sanity check */
	if (s == NULL)
		return (NULL);

	return (bytes_from_raw(s, strlen(s)));
}


struct bytes *
bytes_from_hex(const char *s)
{
	size_t hexlen, nbytes;
	struct bytes *buf = NULL;
	int success = 0;

	/* sanity check */
	if (s == NULL)
		goto cleanup;

	/* each byte is encoded as a pair of hex characters, thus if we have an
	   odd count of character we can't decode successfully the string. */
	hexlen = strlen(s);
	nbytes = hexlen / 2;
	if (nbytes * 2 != hexlen)
		goto cleanup;

	buf = malloc(sizeof(struct bytes) + nbytes * sizeof(uint8_t));
	if (buf == NULL)
		goto cleanup;
	buf->len = nbytes;

	/* decoding loop */
	for (size_t i = 0; i < nbytes; i++) {
		uint8_t msb, lsb; /* 4-bit groups */

		/* first group */
		char c = s[i * 2];
		if (c >= '0' && c <= '9')
			msb = c - '0';
		else if (c >= 'a' && c <= 'f')
			msb = 10 + c - 'a';
		else if (c >= 'A' && c <= 'F')
			msb = 10 + c - 'A';
		else
			goto cleanup;

		/* second group */
		c = s[i * 2 + 1];
		if (c >= '0' && c <= '9')
			lsb = c - '0';
		else if (c >= 'a' && c <= 'f')
			lsb = 10 + c - 'a';
		else if (c >= 'A' && c <= 'F')
			lsb = 10 + c - 'A';
		else
			goto cleanup;

		/* construct the current byte using msb and lsb */
		buf->data[i] = (msb << 4) | lsb;
	}

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		bytes_free(buf);
		buf = NULL;
	}
	return (buf);
}


struct bytes *
bytes_from_base64(const char *s)
{
	size_t i;
	struct bytes *buf = NULL;
	int success = 0;

	/* sanity check */
	if (s == NULL)
		goto cleanup;

	/*
	 * base64 encode 6 bits per character. A "unit" is three bytes (i.e. 24
	 * bits) that are represented as four characters in base64. A valid
	 * base64-encoded string with padding has a character count that is a
	 * multiple of four.
	 */
	const size_t b64len = strlen(s);
	const size_t nunit = b64len / 4;
	if (nunit * 4 != b64len)
		goto cleanup;

	/*
	 * the resulting buffer length is three bytes per unit. If the last unit
	 * is "incomplete" then we can subtract one byte per padding character
	 * `=', up to two.
	 */
	size_t nbytes = nunit * 3;
	size_t rbytes = 0;
	if (nunit > 0 && s[b64len - 1] == '=') {
		if (s[b64len - 2] == '=') {
			rbytes  = 1;
			nbytes -= 2;
		} else {
			rbytes  = 2;
			nbytes -= 1;
		}
	}

	buf = malloc(sizeof(struct bytes) + nbytes * sizeof(uint8_t));
	if (buf == NULL)
		goto cleanup;
	buf->len = nbytes;

	/* decoding loop */
	for (i = 0; i < nunit; i++) {
		int last = (i == (nunit - 1));
		/* the four characters of the current unit */
		const uint8_t c0 = b64decode(s[i * 4]);
		const uint8_t c1 = b64decode(s[i * 4 + 1]);
		const uint8_t c2 = (last && rbytes == 1 ?
		    0x0 : b64decode(s[i * 4 + 2]));
		const uint8_t c3 = (last && rbytes > 0 ?
		    0x0 : b64decode(s[i * 4 + 3]));
		/* sanity check */
		if (c0 == UINT8_MAX || c1 == UINT8_MAX || c2 == UINT8_MAX ||
		    c3 == UINT8_MAX) {
			goto cleanup;
		}
		/* pointer to the first byte of the current unit */
		uint8_t * const p = buf->data + (i * 3);
		/* first byte: all six bits from the first character followed by
		   the leading two bits from the second character */
		p[0] = (c0 << 2) | (c1 >> 4);
		if (last && rbytes == 1)
			continue;
		/* second byte: trailing four bits from the second character
		   followed by the first four bits from the third character */
		p[1] = (c1 << 4) | (c2 >> 2);
		if (last && rbytes == 2)
			continue;
		/* third byte: trailing two bits of the third character followed
		   by all six bits from the fourth character */
		p[2] = (c2 << 6) | c3;
	}

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		bytes_free(buf);
		buf = NULL;
	}
	return (buf);
}


struct bytes *
bytes_dup(const struct bytes *src)
{
	size_t len;
	struct bytes *cpy = NULL;

	/* sanity check */
	if (src == NULL)
		return (NULL);

	len = src->len;
	cpy = malloc(sizeof(struct bytes) + len * sizeof(uint8_t));
	if (cpy == NULL)
		return (NULL);

	cpy->len = len;
	(void)memcpy(cpy->data, src->data, len);

	return (cpy);
}


struct bytes *
bytes_slice(const struct bytes *src, size_t offset, size_t len)
{
	/* sanity checks */
	if (src == NULL)
		return (NULL);
	if (offset + len > src->len)
		return (NULL);

	return (bytes_from_raw(src->data + offset, len));
}


intmax_t
bytes_hamming_distance(const struct bytes *a, const struct bytes *b)
{
	/* sanity checks */
	if (a == NULL || b == NULL)
		return (-1);
	if (a->len != b->len)
		return (-1);

	intmax_t d = 0;
	for (size_t i = 0; i < a->len; i++)
		d += popcnt(a->data[i] ^ b->data[i]);

	return (d);
}


char *
bytes_to_str(const struct bytes *bytes)
{
	char *str = NULL;

	/* sanity check */
	if (bytes == NULL)
		return (NULL);

	const size_t len = bytes->len;
	/* one additional character for the terminating NUL. */
	str = malloc(len + 1);
	if (str == NULL)
		return (NULL);

	(void)memcpy(str, bytes->data, len);
	/* NUL-terminated the result string */
	str[len] = '\0';

	return (str);
}


char *
bytes_to_hex(const struct bytes *bytes)
{
	/* table of base16 index to character as per § 8 */
	static const char b16table[16] = "0123456789ABCDEF";
	char *str = NULL;

	/* sanity check */
	if (bytes == NULL)
		return (NULL);

	const size_t b16len = bytes->len * 2;
	/* one additional character for the terminating NUL. */
	str = malloc(b16len + 1);
	if (str == NULL)
		return (NULL);

	for (size_t i = 0; i < bytes->len; i++) {
		const uint8_t byte = bytes->data[i];
		/* pointer to the first character of the current unit */
		char * const p = str + (i * 2);
		p[0] = b16table[byte >> 4];  /* "higher" 4-bit group */
		p[1] = b16table[byte & 0xf]; /* "lower" 4-bit group */
	}

	/* NUL-terminated the result string */
	str[b16len] = '\0';
	return (str);
}


char *
bytes_to_base64(const struct bytes *bytes)
{
	/* table of base64 index to character as per § 4 */
	static const char b64table[64] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	/* the base64 padding character */
	static const char b64pad = '=';

	size_t i;
	char *str = NULL;

	/* sanity check */
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
	const size_t nunit = bytes->len / 3;
	const size_t rbytes = bytes->len % 3;
	const size_t b64len = 4 * (nunit + (rbytes ? 1 : 0));

	/* one additional character for the terminating NUL. */
	str = malloc(b64len + 1);
	if (str == NULL)
		return (NULL);

	/* encoding loop */
	for (i = 0; i < nunit; i++) {
		/* the three bytes of the current unit */
		const uint8_t b0 = bytes->data[i * 3];
		const uint8_t b1 = bytes->data[i * 3 + 1];
		const uint8_t b2 = bytes->data[i * 3 + 2];
		/* pointer to the first character of the current unit */
		char * const p = str + (i * 4);
		/* first character: leading six bits of the first byte */
		p[0] = b64table[b0 >> 2];
		/* second character: trailing two bits of the first byte
		   followed by the leading four bits of the second byte. */
		p[1] = b64table[((b0 & 0x03) << 4) | (b1 >> 4)];
		/* third character: trailing four bits of the second byte
		   followed by the leading two bits of the third byte. */
		p[2] = b64table[((b1 & 0x0f) << 2) | (b2 >> 6)];
		/* fourth character: trailing six bits of the third byte */
		p[3] = b64table[b2 & 0x3f];
	}

	/* check if we have a final unit to encode with padding */
	if (rbytes > 0) {
		/* pointer to the first character of the final unit */
		char * const p = str + (i * 4);
		if (rbytes == 2) {
			/* this unit is short of exactly one byte. In other
			   words, there are two bytes available for this unit,
			   thus we'll need one padding character. */
			const uint8_t b0 = bytes->data[i * 3];
			const uint8_t b1 = bytes->data[i * 3 + 1];
			const uint8_t b2 = 0;
			p[0] = b64table[b0 >> 2];
			p[1] = b64table[((b0 & 0x03) << 4) | (b1 >> 4)];
			p[2] = b64table[((b1 & 0x0f) << 2) | (b2 >> 6)];
			p[3] = b64pad;
		} else if (rbytes == 1) {
			/* this unit is short of two bytes. In other
			   words, there are only one byte available for this
			   unit, thus we'll need two padding characters. */
			const uint8_t b0 = bytes->data[i * 3];
			const uint8_t b1 = 0;
			p[0] = b64table[b0 >> 2];
			p[1] = b64table[((b0 & 0x03) << 4) | (b1 >> 4)];
			p[2] = b64pad;
			p[3] = b64pad;
		}
	}

	/* NUL-terminated the result string */
	str[b64len] = '\0';
	return (str);
}


void
bytes_free(struct bytes *victim)
{
	size_t len;

	if (victim == NULL)
		return;

	len = (sizeof(struct bytes) + victim->len * sizeof(uint8_t));
	freezero(victim, len);
}
