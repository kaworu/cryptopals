/*
 * break_rsa.c
 *
 * RSA e=3 broadcast attack stuff.
 */
#include "break_rsa.h"
#include "mpi.h"


struct bytes *
rsa_e3_broadcast_attack(
		    const struct bytes *bc0, const struct rsa_pubkey *k0,
		    const struct bytes *bc1, const struct rsa_pubkey *k1,
		    const struct bytes *bc2, const struct rsa_pubkey *k2)
{
	struct bytes *plaintext = NULL;
	struct mpi *c0 = NULL, *c1 = NULL, *c2 = NULL;
	struct mpi *ms0 = NULL, *ms1 = NULL, *ms2 = NULL;
	struct mpi *r0 = NULL, *r1 = NULL, *r2 = NULL;
	struct mpi *n012 = NULL, *sum = NULL, *root = NULL;
	int success = 0;

	/* sanity checks */
	if (bc0 == NULL || bc1 == NULL || bc2 == NULL)
		goto cleanup;
	if (k0 == NULL || k1 == NULL || k2 == NULL)
		goto cleanup;

	c0 = mpi_from_bytes_be(bc0);
	c1 = mpi_from_bytes_be(bc1);
	c2 = mpi_from_bytes_be(bc2);

	ms0 = mpi_mul(k1->n, k2->n);
	ms1 = mpi_mul(k0->n, k2->n);
	ms2 = mpi_mul(k0->n, k1->n);

	r0 = mpi_mod_inv(ms0, k0->n);
	r1 = mpi_mod_inv(ms1, k1->n);
	r2 = mpi_mod_inv(ms2, k2->n);

	if (mpi_mul_mut(r0, ms0) != 0)
		goto cleanup;
	if (mpi_mul_mut(r1, ms1) != 0)
		goto cleanup;
	if (mpi_mul_mut(r2, ms2) != 0)
		goto cleanup;

	if (mpi_mul_mut(r0, c0) != 0)
		goto cleanup;
	if (mpi_mul_mut(r1, c1) != 0)
		goto cleanup;
	if (mpi_mul_mut(r2, c2) != 0)
		goto cleanup;

	sum = mpi_add(r0, r1);
	if (mpi_add_mut(sum, r2) != 0)
		goto cleanup;

	n012 = mpi_mul(k0->n, k1->n);
	if (mpi_mul_mut(n012, k2->n) != 0)
		goto cleanup;

	if (mpi_mod_mut(sum, n012) != 0)
		goto cleanup;

	root = mpi_cbrt(sum);
	plaintext = mpi_to_bytes_be(root);
	if (plaintext == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	mpi_free(root);
	mpi_free(n012);
	mpi_free(sum);
	mpi_free(r2);
	mpi_free(r1);
	mpi_free(r0);
	mpi_free(ms2);
	mpi_free(ms1);
	mpi_free(ms0);
	mpi_free(c2);
	mpi_free(c1);
	mpi_free(c0);
	if (!success) {
		bytes_free(plaintext);
		plaintext = NULL;
	}
	return plaintext;
}
