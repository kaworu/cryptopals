#ifndef BREAK_SRP_H
#define BREAK_SRP_H
/*
 * break_srp.h
 *
 * Secure Remote Password (SRP) parameters injection stuff.
 */
#include "srp.h"


/*
 * Types of SRP spoofing attack.
 */
enum srp_spoof_client_type {
	/*
	 * Pass zero as A to the server. This effectively set the private shared
	 * secret number to 0.
	 *
	 * This attack is described in Set 5 / Challenge 37.
	 */
	SRP_SPOOF_CLIENT_0_AS_A,

	/*
	 * Pass N as A to the server. This effectively set the private shared
	 * secret number to 0.
	 *
	 * This attack is described in Set 5 / Challenge 37.
	 */
	SRP_SPOOF_CLIENT_N_AS_A,
};

/*
 * opaque struct used by client created by srp_spoof_client_new().
 */
struct srp_spoof_client_opaque {
	enum srp_spoof_client_type type;

	/*
	 * The SRP identifier we want to impersonate.
	 */
	struct bytes *I;
};


/*
 * Create a new SRP spoofing Client struct of the given type.
 *
 * Returns a new srp_client struct that must be passed to its free function
 * member, or NULL on failure.
 */
struct srp_client	*srp_spoof_client_new(enum srp_spoof_client_type type,
		    const struct bytes *I);

#endif /* ndef BREAK_SRP_H */
