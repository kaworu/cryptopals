#ifndef COMPAT_EXPLICIT_BZERO_H
#define COMPAT_EXPLICIT_BZERO_H
/*
 * compat/explicit_bzero.h
 *
 * à-la OpenBSD explicit_bzero(3).
 */
#include <stddef.h>


void	explicit_bzero(void *ptr, size_t size);

#endif /* ndef COMPAT_EXPLICIT_BZERO_H */
