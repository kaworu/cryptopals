#ifndef COMPAT_FREEZERO_H
#define COMPAT_FREEZERO_H
/*
 * compat/freezero.h
 *
 * à-la OpenBSD freezero(3).
 */
#include <stddef.h>


void	freezero(void *ptr, size_t size);

#endif /* ndef COMPAT_FREEZERO_H */
