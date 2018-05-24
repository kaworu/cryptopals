/*
 * break_cbc.c
 *
 * CBC analysis stuff for cryptopals.com challenges.
 */
#include <string.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "compat.h"
#include "aes.h"
#include "break_cbc.h"

#define	CBC_BITFLIPPING_PREFIX	"comment1=cooking%20MCs;userdata="
#define	CBC_BITFLIPPING_SUFFIX	";comment2=%20like%20a%20pound%20of%20bacon"


struct bytes *
cbc_bitflipping_oracle(const struct bytes *payload,
		    const struct bytes *key, const struct bytes *iv)
{
	struct bytes *before = NULL, *after = NULL, *quoted = NULL;
	struct bytes *plaintext = NULL, *ciphertext = NULL;
	int success = 0;

	/* sanity checks */
	if (payload == NULL || key == NULL || iv == NULL)
		goto cleanup;

	/* compute the payload final length, since we need to quote out the ";"
	   and "=" characters. */
	size_t len = 0;
	for (size_t i = 0; i < payload->len; i++) {
		switch (payload->data[i]) {
		case '=':
		case ';':
			len += 3;
			break;
		default:
			len += 1;
		}
	}

	/* build the quoted version of payload */
	quoted = bytes_zeroed(len);
	if (quoted == NULL)
		goto cleanup;
	uint8_t *p = quoted->data;
	for (size_t i = 0; i < payload->len; i++) {
		switch (payload->data[i]) {
		case '=':
			(void)memcpy(p, "%3D", 3);
			p += 3;
			break;
		case ';':
			(void)memcpy(p, "%3B", 3);
			p += 3;
			break;
		default:
			*p++ = payload->data[i];
		}
	}

	/* build the full plaintext to encrypt */
	before = bytes_from_str(CBC_BITFLIPPING_PREFIX);
	after  = bytes_from_str(CBC_BITFLIPPING_SUFFIX);
	const struct bytes *const parts[] = { before, quoted, after };
	plaintext = bytes_joined_const(parts, sizeof(parts) / sizeof(*parts));

	/* encrypt the plaintext using AES-CBC */
	ciphertext = aes_128_cbc_encrypt(plaintext, key, iv);
	if (ciphertext == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(plaintext);
	bytes_free(after);
	bytes_free(before);
	bytes_free(quoted);
	if (!success) {
		bytes_free(ciphertext);
		ciphertext = NULL;
	}
	return (ciphertext);
}


int
cbc_bitflipping_verifier(const struct bytes *ciphertext,
		    const struct bytes *key, const struct bytes *iv)
{
	struct bytes *plaintext = NULL;
	char *s = NULL;
	int success = 0;
	int admin = 0;

	plaintext = aes_128_cbc_decrypt(ciphertext, key, iv);
	s = bytes_to_str(plaintext);
	if (s == NULL)
		goto cleanup;

	admin = (strstr(s, ";admin=true;") != NULL);

	success = 1;
	/* FALLTHROUGH */
cleanup:
	freezero(s, s == NULL ? 0 : strlen(s));
	bytes_free(plaintext);
	return (success ? admin : -1);
}


struct bytes *
cbc_bitflipping_breaker(const void *key, const void *iv)
{
#define oracle(x)	cbc_bitflipping_oracle((x), key, iv)
	const EVP_CIPHER *cipher = EVP_aes_128_cbc();
	const size_t blocksize = EVP_CIPHER_block_size(cipher);
	struct bytes *pad = NULL, *scrambled = NULL;
	struct bytes *admin = NULL, *payload = NULL, *ciphertext = NULL;
	int success = 0;

	/* given the prefix length, compute how much padding bytes we need to
	   add so that it is congruent to 0 modulo blocksize */
	const size_t prefixlen = strlen(CBC_BITFLIPPING_PREFIX);
	const size_t padlen = prefixlen % blocksize == 0 ? 0 :
		    blocksize - strlen(CBC_BITFLIPPING_PREFIX) % blocksize;
	pad = bytes_repeated(padlen, 'A');

	/* generate a full block on which we will hack the bytes in order to
	   bitflip the block right after it */
	const size_t sblock = (prefixlen + padlen) / blocksize;
	scrambled = bytes_repeated(blocksize, 'X');

	/* the admin=true payload. We use a comma (,), dash (-), to be flipped
	   into a semi-colon (;), respectively equal (=). */
	const size_t sci = sblock * blocksize + 0;
	const size_t eqi = sblock * blocksize + 6;
	admin = bytes_from_str(",admin-true");

	/* generate the ciphertext using the oracle */
	const struct bytes *const parts[] = { pad, scrambled, admin };
	payload = bytes_joined_const(parts, sizeof(parts) / sizeof(*parts));
	ciphertext = oracle(payload);
	if (ciphertext == NULL)
		goto cleanup;

	/* mess with the scrambled block */
	ciphertext->data[sci] ^= (',' ^ ';');
	ciphertext->data[eqi] ^= ('-' ^ '=');

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(payload);
	bytes_free(admin);
	bytes_free(scrambled);
	bytes_free(pad);
	if (!success) {
		bytes_free(ciphertext);
		ciphertext = NULL;
	}
	return (ciphertext);
#undef oracle
}
