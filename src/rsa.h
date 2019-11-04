#ifndef SRC_RSA_H
#define SRC_RSA_H
/*
 * src/rsa.h
 *
 * RSA stuff for cryptopals.com challenges.
 */
#include <stddef.h>
#include "bytes.h"


/*
 * a RSA private key that can be used for decryption.
 */
struct rsa_privkey;

/*
 * a RSA public key that can be used for encryption.
 */
struct rsa_pubkey;


/*
 * Generate a RSA private / public key pair of the requested bit count.
 *
 * Key generation for RSA public-key encryption,
 * see the Handbook of Applied Cryptography §8.1.
 *
 * Returns 0 on success, -1 on failure. On success, both privk_p and pubk_p are
 * set to the private respectively public part of the RSA key pair and must be
 * passed to rsa_privkey_free() respectively rsa_pubkey_free() after use.
 */
int	rsa_keygen(const size_t bits, struct rsa_privkey **privk_p,
		    struct rsa_pubkey **pubk_p);

/*
 * Encrypt the given plaintext with the provided RSA public key.
 *
 * RSA public-key encryption
 * see the Handbook of Applied Cryptography §8.3.
 *
 * Returns the resulting ciphertext on success, NULL on failure. The returned
 * value should be passeed to bytes_free() after use.
 */
struct bytes	*rsa_encrypt(const struct bytes *plaintext,
		    const struct rsa_pubkey *pubk);

/*
 * Decrypt the given ciphertext with the provided RSA private key.
 *
 * RSA public-key decryption,
 * see the Handbook of Applied Cryptography §8.3.
 *
 * Returns the resulting plaintext on success, NULL on failure. The returned
 * value should be passeed to bytes_free() after use.
 */
struct bytes	*rsa_decrypt(const struct bytes *ct,
		    const struct rsa_privkey *privk);

/*
 * Free the resource associated with the given RSA private key struct.
 *
 * If not NULL, the data will be zero'd before freed.
 */
void	rsa_privkey_free(struct rsa_privkey *privk);

/*
 * Free the resource associated with the given RSA public key struct.
 *
 * If not NULL, the data will be zero'd before freed.
 */
void	rsa_pubkey_free(struct rsa_pubkey *pubk);

#endif /* ndef SRC_RSA_H */
