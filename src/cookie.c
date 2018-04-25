/*
 * cookie.c
 *
 * Cookie stuff for Set 2 / Challenge 13.
 */
#include <stdlib.h>
#include <string.h>

#include "compat.h"
#include "uri.h"
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
		char *key   = uri_decode(p);
		char *value = uri_decode(eq + 1);
		const int ret = cookie_append(decoded, key, value);
		freezero(value, value == NULL ? 0 : strlen(value));
		freezero(key,   key == NULL ? 0 : strlen(key));
		if (ret != 0)
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
		/* key length computation */
		size_t len = 0;
		if (uri_encode_len(kv->key, &len) != 0)
			goto cleanup;
		siz += len;
		/* account for the joining `=' */
		siz += 1;
		/* value length computation */
		if (uri_encode_len(kv->value, &len) != 0)
			goto cleanup;
		siz += len;
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
		char *s = uri_encode(kv->key);
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
		s = uri_encode(kv->value);
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
	if (victim != NULL) {
		struct cookie_kv *kv = victim->head;
		while (kv != NULL) {
			freezero(kv->key,   strlen(kv->key));
			freezero(kv->value, strlen(kv->value));
			struct cookie_kv *next = kv->next;
			freezero(kv, sizeof(struct cookie_kv));
			kv = next;
		}
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
