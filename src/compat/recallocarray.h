#ifndef COMPAT_RECALLOCARRAY_H
#define COMPAT_RECALLOCARRAY_H
/*
 * compat/recallocarray.h
 *
 * à-la OpenBSD recallocarray(3).
 */
#include <stddef.h>


void	*recallocarray(void *ptr, size_t oldnmemb, size_t newnmemb,
		    size_t size);

#endif /* ndef COMPAT_RECALLOCARRAY_H */
