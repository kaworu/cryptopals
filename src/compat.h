#ifndef COMPAT_H
#define COMPAT_H
/*
 * compat.h
 *
 * Compatibility stuff.
 */

#if defined(HAVE_EXPLICIT_MEMSET)
#include <string.h>
#else
#include "compat/explicit_memset.h"
#endif

#if defined(HAVE_EXPLICIT_BZERO)
#include <strings.h>
#else
#include "compat/explicit_bzero.h"
#endif

#if defined(HAVE_FREEZERO)
#include <stdlib.h>
#else
#include "compat/freezero.h"
#endif

#endif /* ndef COMPAT_H */
