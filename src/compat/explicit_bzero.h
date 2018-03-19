#ifndef EXPLICIT_BZERO_H
#define EXPLICIT_BZERO_H
/*
 * explicit_bzero.h
 *
 * à-la OpenBSD explicit_bzero(3).
 */

void	explicit_bzero(void *buf, size_t len);

#endif /* ndef EXPLICIT_BZERO_H */
