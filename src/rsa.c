/*
 * src/rsa.c
 *
 * RSA stuff for cryptopals.com challenges.
 */
#include <stdlib.h>

#include "compat.h"
#include "rsa.h"
#include "mpi.h"


struct rsa_privkey {
	struct mpi *d, *n;
};

struct rsa_pubkey {
	struct mpi *e, *n;
};


/*
 * Key generation for RSA public-key encryption,
 * see the Handbook of Applied Cryptography §8.1.
 */
int
rsa_keygen(const size_t bits, struct rsa_privkey **privk_p,
		    struct rsa_pubkey **pubk_p)
{
	struct mpi *p = NULL, *q = NULL, *n = NULL, *ndup = NULL;
	struct mpi *p_1 = NULL, *q_1 = NULL;
	struct mpi *phi = NULL, *e = NULL;
	struct mpi *d = NULL;
	struct rsa_privkey *privk = NULL;
	struct rsa_pubkey *pubk = NULL;
	int success = 0;

	/* sanity checks */
	if (privk_p == NULL || pubk_p == NULL)
		goto cleanup;

	/* p and q primes generation loop */
	do {
		/* cleanup from the previous iteration, if any */
		mpi_free(q_1);
		mpi_free(p_1);
		mpi_free(q);
		mpi_free(p);
		/* generate p and q */
		p = mpi_probable_prime(bits / 2);
		q = mpi_probable_prime(bits / 2);
		p_1 = mpi_subn(p, 1);
		q_1 = mpi_subn(q, 1);
		if (p == NULL || q == NULL || p_1 == NULL || q_1 == NULL)
			goto cleanup;
		/*
		 * Since we use e = 3, it is necessary that neither p - 1
		 * nor q - 1 be divisible by 3.
		 * See the Handbook of Applied Cryptography, Note 8.9 (ii).
		 */
	} while (mpi_modn(p_1, 3) == 0 || mpi_modn(q_1, 3) == 0);

	/* compute the private decryption exponent d */
	phi = mpi_mul(p_1, q_1);
	e   = mpi_from_hex("3");
	if (phi == NULL || e == NULL)
		goto cleanup;
	d = mpi_mod_inv(e, phi);
	if (d == NULL)
		goto cleanup;

	/* compute the modulus n */
	n = mpi_mul(p, q);
	ndup = mpi_dup(n);
	if (n == NULL || ndup == NULL)
		goto cleanup;

	privk = calloc(1, sizeof(struct rsa_privkey));
	pubk  = calloc(1, sizeof(struct rsa_pubkey));
	if (privk == NULL || pubk == NULL)
		goto cleanup;

	success = 1;

	/* setup privk and pubk members */
	privk->d = d;
	d = NULL;
	privk->n = n;
	n = NULL;
	pubk->e = e;
	e = NULL;
	pubk->n = ndup;
	ndup = NULL;

	/* "return" the private and public keys */
	*privk_p = privk;
	privk = NULL;
	*pubk_p = pubk;
	pubk = NULL;

	/* FALLTHROUGH */
cleanup:
	rsa_pubkey_free(pubk);
	rsa_privkey_free(privk);
	mpi_free(ndup);
	mpi_free(e);
	mpi_free(phi);
	mpi_free(q_1);
	mpi_free(p_1);
	mpi_free(ndup);
	mpi_free(n);
	mpi_free(q);
	mpi_free(p);
	return (success ? 0 : -1);
}


/*
 * RSA public-key encryption
 * see the Handbook of Applied Cryptography §8.3.
 */
struct bytes *
rsa_encrypt(const struct bytes *plaintext, const struct rsa_pubkey *pubk)
{
	struct mpi *m = NULL, *c = NULL;
	struct bytes *ciphertext = NULL;
	int success = 0;

	/* sanity checks */
	if (plaintext == NULL || pubk == NULL)
		goto cleanup;

	m = mpi_from_bytes_be(plaintext);
	if (m == NULL || mpi_cmp(m, pubk->n) >= 0)
		goto cleanup;

	c = mpi_mod_exp(m, pubk->e, pubk->n);
	if (c == NULL)
		goto cleanup;

	ciphertext = mpi_to_bytes_be(c);
	if (ciphertext == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	mpi_free(c);
	mpi_free(m);
	if (!success) {
		bytes_free(ciphertext);
		ciphertext = NULL;
	}
	return ciphertext;
}

/*
 * RSA public-key decryption,
 * see the Handbook of Applied Cryptography §8.3.
 */
struct bytes *
rsa_decrypt(const struct bytes *ciphertext, const struct rsa_privkey *privk)
{
	struct mpi *c = NULL, *m = NULL;
	struct bytes *plaintext = NULL;
	int success = 0;

	/* sanity checks */
	if (ciphertext == NULL || privk == NULL)
		goto cleanup;

	c = mpi_from_bytes_be(ciphertext);
	if (c == NULL || mpi_cmp(c, privk->n) >= 0)
		goto cleanup;

	m = mpi_mod_exp(c, privk->d, privk->n);
	if (m == NULL)
		goto cleanup;

	plaintext = mpi_to_bytes_be(m);
	if (plaintext == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	mpi_free(m);
	mpi_free(c);
	if (!success) {
		bytes_free(plaintext);
		plaintext = NULL;
	}
	return plaintext;
}


void
rsa_privkey_free(struct rsa_privkey *privk)
{
	if (privk == NULL)
		return;
	mpi_free(privk->d);
	mpi_free(privk->n);
	freezero(privk, sizeof(struct rsa_privkey));
}


void
rsa_pubkey_free(struct rsa_pubkey *pubk)
{
	if (pubk == NULL)
		return;
	mpi_free(pubk->e);
	mpi_free(pubk->n);
	freezero(pubk, sizeof(struct rsa_pubkey));
}
