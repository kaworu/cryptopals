#ifndef COOKIE_H
#define COOKIE_H
/*
 * cookie.h
 *
 * Cookie stuff for Set 2 / Challenge 13.
 */


/* A structured cookie, i.e. a k=v object. */
struct cookie;
/* A k=v cookie member */
struct cookie_kv;


/*
 * Create a new cookie object.
 *
 * Returns a pointer to a newly allocated cookie struct that should passed to
 * cookie_free(). Returns NULL if malloc(3) failed.
 */
struct cookie	*cookie_alloc(void);

/*
 * Decode the given cookie from a NUL-terminated string.
 *
 * Returns a pointer to a newly allocated cookie struct that should passed to
 * cookie_free(). Returns NULL on parsing failure or if malloc(3) failed.
 */
struct cookie	*cookie_decode(const char *s);

/*
 * Compute the count of k=v in the given cookie.
 *
 * The result is stored in count_p if it is not NULL.
 *
 * Returns 0 on success, -1 on error.
 */
int	cookie_count(const struct cookie *cookie, size_t *count_p);

/*
 * Returns the k=v member at the requested index (0-indexed) or NULL on failure
 * (index out of bound, cookie is NULL).
 *
 * The returned pointer is owned by the given cookie and thus must not be used
 * once the cookie has been cookie_free()'d.
 */
const struct cookie_kv	*cookie_at(const struct cookie *cookie, size_t index);

/*
 * Returns the k=v member matching the given key or NULL on failure (key not
 * found, cookie is NULL).
 *
 * NOTE: it is possible to have more than one member with the same key. In this
 * case the approach retained by this implementation is first given, i.e. the
 * matching member with the smallest index will be returned.
 *
 * The returned pointer is owned by the given cookie and thus must not be used
 * once the cookie has been cookie_free()'d.
 */
const struct cookie_kv	*cookie_get(const struct cookie *cookie,
		    const char *key);

/*
 * Append a k=v to the given cookie.
 *
 * Returns 0 on success, -1 if malloc(3) failed.
 */
int	cookie_append(struct cookie *cookie,
		    const char *key, const char *value);

/*
 * Encode the given cookie into a NUL-terminated string.
 *
 * Returns a pointer to a newly allocated NUL-terminated string that should
 * passed to free(). Returns NULL if the given pointer is NULL, or malloc(3)
 * failed.
 */
char	*cookie_encode(const struct cookie *cookie);

/*
 * Free the resource associated with the given cookie struct.
 *
 * If not NULL, the data will be zero'd before freed.
 */
void	cookie_free(struct cookie *victim);

/*
 * Returns the key of the given k=v member, or NULL on error.
 *
 * The returned pointer is owned by the given cookie_kv and thus must not be
 * used once its cookie has been cookie_free()'d.
 */
const char	*cookie_kv_key(const struct cookie_kv *kv);

/*
 * Returns the value of the given k=v member, or NULL on error.
 *
 * The returned pointer is owned by the given cookie_kv and thus must not be
 * used once its cookie has been cookie_free()'d.
 */
const char	*cookie_kv_value(const struct cookie_kv *kv);

#endif /* ndef COOKIE_H */
