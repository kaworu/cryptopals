#ifndef COMPAT_EXPLICIT_BZERO_H
#define COMPAT_EXPLICIT_BZERO_H
/*
 * compat/explicit_bzero.h
 *
 * à-la OpenBSD explicit_bzero(3).
 */
#include <stddef.h>


void	explicit_bzero(void *buf, size_t len);

#endif /* ndef COMPAT_EXPLICIT_BZERO_H */
