#ifndef COMPAT_EXPLICIT_MEMSET_H
#define COMPAT_EXPLICIT_MEMSET_H
/*
 * compat/explicit_memset.h
 *
 * à-la NetBSD explicit_memset(3).
 */
#include <stddef.h>


void	*explicit_memset(void *ptr, int c, size_t size);

#endif /* ndef COMPAT_EXPLICIT_MEMSET_H */
