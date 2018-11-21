#ifndef COMPAT_H
#define COMPAT_H
/*
 * compat.h
 *
 * Compatibility stuff.
 */

#if defined(HAVE_REALLOCARRAY)
#include <stdlib.h>
#else
#include "compat/reallocarray.h"
#endif

#if defined(HAVE_RECALLOCARRAY)
#include <stdlib.h>
#else
#include "compat/recallocarray.h"
#endif

#if defined(HAVE_FREEZERO)
#include <stdlib.h>
#else
#include "compat/freezero.h"
#endif

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

#if defined(HAVE_TIMINGSAFE_BCMP)
#include <string.h>
#else
#include "compat/timingsafe_bcmp.h"
#endif

#if defined(HAVE_STRLCPY)
#include <string.h>
#else
#include "compat/strlcpy.h"
#endif

#if defined(HAVE_STRLCAT)
#include <string.h>
#else
#include "compat/strlcat.h"
#endif

#if defined(HAVE_ASPRINTF)
#include <stdio.h>
#else
#include "compat/asprintf.h"
#endif

#endif /* ndef COMPAT_H */
