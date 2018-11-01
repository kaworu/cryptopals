#ifndef SRP_H
#define SRP_H
/*
 * srp.h
 *
 * Secure Remote Password (SRP) stuff for cryptopals.com challenges.
 */
#include "bignum.h"
#include "bytes.h"


/*
 * Used to simulate a SRP server, having methods instead of network calls.
 */
struct srp_server {
	/*
	 * The SRP parameters agreed upon with the client before any
	 * communication is made.
	 */
	struct bignum *N, *g, *k;
	struct bytes *I, *P;

	/*
	 * The shared private key derived from the SRP protocol.
	 */
	struct bytes *key;

	/*
	 * The private challenge that is created by start() and checked by
	 * finalize().
	 */
	struct bytes *token;

	/*
	 * Called by the client to start a SRP password-authenticated key
	 * agreement.
	 *
	 * The caller must provide I (its identity) and A (public number
	 * generated à-la Diffie-Hellman).
	 *
	 * On success salt_p is set to the SRP salt, B_p to the server's public
	 * number, and both salt_p and B_p must be passed to bytes_free() by the
	 * caller.
	 *
	 * Returns 0 on success, -1 if the identity is invalid or on failure.
	 */
	int	(*start)(struct srp_server *server,
			    const struct bytes *I, const struct bignum *A,
			    struct bytes **salt_p, struct bignum **B_p);

	/*
	 * Finalize a SRP password-authenticated key agreement by verifying the
	 * provided token.
	 *
	 * ON both success and failure, the token created by start() (if any) is
	 * forgotten by the server once this function returns. Thus, if
	 * finalize() failed the client must re-start() the SRP agreement if
	 * desired.
	 *
	 * On success, a private shared key has been established between the
	 * client and the server that can be used for further communication.
	 *
	 * Returns 0 on success (the token is valid), -1 on failure.
	 */
	int	(*finalize)(struct srp_server *server, const struct bytes *token);
};

/*
 * Used to simulate a SRP server, having and using methods instead of network
 * calls.
 */
struct srp_client {
	/*
	 * The SRP parameters agreed upon with the server before any
	 * communication is made.
	 */
	struct bignum *N, *g, *k;
	struct bytes *I, *P;

	/*
	 * The shared private key derived from the SRP protocol.
	 */
	struct bytes *key;

	/*
	 * Ask the client authenticate itself to the provided server.
	 *
	 * The client will try to start() and finalize() a SRP
	 * password-authenticated key agreement with the server. A successful
	 * authentication means that the client's credentials (it's identity and
	 * password) are recognized as correct by the server, and a private
	 * shared key is created that can be used for further communication.
	 *
	 * Returns 0 on success, -1 on failure.
	 */
	int	(*authenticate)(struct srp_client *client,
			    struct srp_server *server);
};


/*
 * Create a new SRP Server struct with the given parameters.
 *
 * The parameters are expected to be the same as the client that are going to
 * try to authenticate.
 *
 * Returns a new srp_server struct that must be passed to srp_server_free(), or
 * NULL on failure.
 */
struct srp_server	*srp_server_new(const struct bignum *N,
		    const struct bignum *g, const struct bignum *k,
		    const struct bytes *I, const struct bytes *P);

/*
 * Free the resource associated with the given srp_server struct.
 *
 * If not NULL, the data will be zero'd before freed.
 */
void	srp_server_free(struct srp_server *server);


/*
 * Create a new SRP Client struct with the given parameters.
 *
 * The parameters are expected to be the same as the server.
 *
 * Returns a new srp_client struct that must be passed to srp_client_free(), or
 * NULL on failure.
 */
struct srp_client	*srp_client_new(const struct bignum *N,
		    const struct bignum *g, const struct bignum *k,
		    const struct bytes *I, const struct bytes *P);

/*
 * Free the resource associated with the given srp_client struct.
 *
 * If not NULL, the data will be zero'd before freed.
 */
void	srp_client_free(struct srp_client *client);

#endif /* ndef SRP_H */
