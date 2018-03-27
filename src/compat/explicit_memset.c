/*
 * compat/explicit_memset.c
 *
 * à-la NetBSD explicit_memset(3).
 */
#include "compat.h"


/*
 * Taken from https://github.com/NetBSD/src/blob/0bff031265b50be8e8b7719aed82212928d6c1df/common/lib/libc/string/explicit_memset.c
 *
 * Written by Matthias Drochner <drochner@NetBSD.org>.
 * Public domain.
 */
#include <string.h>

/*
 * The use of a volatile pointer guarantees that the compiler
 * will not optimise the call away.
 */
void *(* volatile explicit_memset_impl)(void *, int, size_t) = memset;

void *
explicit_memset(void *ptr, int c, size_t size)
{
	return (*explicit_memset_impl)(ptr, c, size);
}
