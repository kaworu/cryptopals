/*
 * cookie.c
 *
 * Cookie stuff for Set 2 / Challenge 13.
 */
#include <stdlib.h>
#include <string.h>

#include "compat.h"
#include "cookie.h"


struct cookie_kv {
	char *key, *value;
	struct cookie_kv *next;
};


struct cookie {
	size_t count;
	struct cookie_kv *head;
	struct cookie_kv *tail;
};


/*
 * Return a copy of the given NUL-terminated string `src' without the special
 * cookie characters `=' and `&', or NULL if `src' is NULL or malloc(3) failed.
 */
static char *
cookie_escape(const char *src)
{
	char *escaped = NULL;

	/* sanity check */
	if (src == NULL)
		return (NULL);

	const size_t len = strlen(src);
	escaped = calloc(len + 1, sizeof(char));
	if (escaped == NULL)
		return (NULL);

	char *dest = escaped;
	for (const char *p = src; *p != '\0'; p++) {
		if (*p != '&' && *p != '=')
			*dest++ = *p;
	}

	return (escaped);
}


struct cookie *
cookie_alloc(void)
{
	return (calloc(1, sizeof(struct cookie)));
}


struct cookie *
cookie_decode(const char *s)
{
	char *cpy = NULL;
	struct cookie *decoded = NULL;
	int success = 0;

	/* sanity check */
	if (s == NULL)
		goto cleanup;

	decoded = cookie_alloc();
	if (decoded == NULL)
		goto cleanup;

	cpy = strdup(s);
	if (cpy == NULL)
		goto cleanup;

	char *last = NULL;
	for (char *p = strtok_r(cpy, "&", &last); p != NULL;
		    p = strtok_r(NULL, "&", &last)) {
		char *eq = strchr(p, '=');
		if (eq == NULL)
			goto cleanup;
		*eq = '\0';
		char *key   = p;
		char *value = eq + 1;
		if (cookie_append(decoded, key, value) != 0)
			goto cleanup;
	}

	success = 1;
	/* FALLTHROUGH */
cleanup:
	freezero(cpy, cpy == NULL ? 0 : strlen(cpy));
	if (!success) {
		cookie_free(decoded);
		decoded = NULL;
	}
	return (decoded);
}


int
cookie_count(const struct cookie *cookie, size_t *count_p)
{
	/* sanity check */
	if (cookie == NULL)
		return (-1);

	if (count_p != NULL)
		*count_p = cookie->count;

	return (0);
}


const struct cookie_kv *
cookie_at(const struct cookie *cookie, size_t index)
{
	const struct cookie_kv *kv = NULL;

	/* sanity check */
	if (cookie == NULL)
		return (NULL);

	for (kv = cookie->head; kv != NULL && index > 0; kv = kv->next)
		index -= 1;

	return (kv);
}


const struct cookie_kv *
cookie_get(const struct cookie *cookie, const char *key)
{
	const struct cookie_kv *kv = NULL;

	/* sanity check */
	if (cookie == NULL || key == NULL)
		return (NULL);

	for (kv = cookie->head; kv != NULL; kv = kv->next) {
		if (strcmp(kv->key, key) == 0)
			break;
	}

	return (kv);
}


int
cookie_append(struct cookie *cookie, const char *key, const char *value)
{
	struct cookie_kv *kv = NULL;
	char *k = NULL, *v = NULL;
	int success = 0;

	/* sanity checks */
	if (cookie == NULL || key == NULL || value == NULL)
		goto cleanup;

	kv = calloc(1, sizeof(struct cookie_kv));
	k  = strdup(key);
	v  = strdup(value);
	if (kv == NULL || k == NULL || v == NULL)
		goto cleanup;
	kv->key   = k;
	kv->value = v;

	if (cookie->head == NULL)
		cookie->head = kv;
	if (cookie->tail != NULL)
		cookie->tail->next = kv;
	cookie->tail = kv;

	cookie->count += 1;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		freezero(kv, sizeof(struct cookie_kv));
		freezero(k, k == NULL ? 0 : strlen(k));
		freezero(v, v == NULL ? 0 : strlen(v));
		kv = NULL;
	}
	return (success ? 0 : -1);
}


char *
cookie_encode(const struct cookie *cookie)
{
	size_t siz = 0;
	char *encoded = NULL;
	struct cookie_kv *kv = NULL;
	int success = 0;

	/* sanity check */
	if (cookie == NULL)
		goto cleanup;

	/* compute the result length */
	for (kv = cookie->head; kv != NULL; kv = kv->next) {
		/* account for the joining `&' if needed */
		if (kv != cookie->head)
			siz += 1;
		/* key */
		siz += strlen(kv->key);
		/* account for the joining `=' */
		siz += 1;
		siz += strlen(kv->value);
	}
	siz += 1; /* trailing NUL */

	encoded = calloc(siz, sizeof(char));
	if (encoded == NULL)
		goto cleanup;

	for (kv = cookie->head; kv != NULL; kv = kv->next) {
		/* joining `&' if needed */
		if (kv != cookie->head) {
			if (strlcat(encoded, "&", siz) >= siz)
				goto cleanup;
		}
		/* key encoding */
		char *s = cookie_escape(kv->key);
		if (s == NULL)
			goto cleanup;
		size_t ret = strlcat(encoded, s, siz);
		freezero(s, strlen(s));
		if (ret >= siz)
			goto cleanup;
		/* joining `=' */
		if (strlcat(encoded, "=", siz) >= siz)
			goto cleanup;
		/* value encoding */
		s = cookie_escape(kv->value);
		if (s == NULL)
			goto cleanup;
		ret = strlcat(encoded, s, siz);
		freezero(s, strlen(s));
		if (ret >= siz)
			goto cleanup;
	}

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		freezero(encoded, siz);
		encoded = NULL;
	}
	return (encoded);
}


void
cookie_free(struct cookie *victim)
{
	if (victim == NULL)
		return;

	struct cookie_kv *kv = victim->head;
	while (kv != NULL) {
		freezero(kv->key,   strlen(kv->key));
		freezero(kv->value, strlen(kv->value));
		struct cookie_kv *next = kv->next;
		freezero(kv, sizeof(struct cookie_kv));
		kv = next;
	}
	freezero(victim, sizeof(struct cookie));
}


const char *
cookie_kv_key(const struct cookie_kv *kv)
{
	return (kv == NULL ? NULL : kv->key);
}


const char *
cookie_kv_value(const struct cookie_kv *kv)
{
	return (kv == NULL ? NULL : kv->value);
}
