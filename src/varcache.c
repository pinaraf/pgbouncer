/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 *
 * Copyright (c) 2007-2009  Marko Kreen, Skype Technologies OÜ
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Operations with server config parameters.
 */

#include "bouncer.h"

#include <usual/pgutil.h>

struct var_lookup {
	const char *name;
	enum VarCacheIdx idx;
};

static const struct var_lookup lookup [] = {
 {"client_encoding",             VClientEncoding },
 {"DateStyle",                   VDateStyle },
 {"TimeZone",                    VTimeZone },
 {"standard_conforming_strings", VStdStr },
 {"application_name",            VAppName },
 {NULL},
};

static struct StrPool *vpool;

static inline struct PStr *get_value(VarCache *cache, const struct var_lookup *lk)
{
	return cache->var_list[lk->idx];
}

const char *varcache_get(VarCache *cache, const char *key)
{
	const struct var_lookup *lk;
	if (!vpool) {
		return NULL;
	}

	for (lk = lookup; lk->name; lk++) {
		if (strcasecmp(lk->name, key) == 0) {
			struct PStr *pstr = get_value(cache, lk);
			if (pstr)
				return pstr->str;
			else
				return NULL;
		}
	}
	
	VarCacheExtended *ext = cache->extended;
    while (ext != NULL)
    {
        if (strcasecmp(key, ext->name->str) == 0) {
            if (ext->value)
                return ext->value->str;
            else
                return NULL;
        }
        ext = ext->next;
    }
	return NULL;
}

bool varcache_set(VarCache *cache, const char *key, const char *value)
{
	const struct var_lookup *lk;
	struct PStr *pstr = NULL;

	if (!vpool) {
		vpool = strpool_create(USUAL_ALLOC);
		if (!vpool)
			return false;
	}

	for (lk = lookup; lk->name; lk++) {
		if (strcasecmp(lk->name, key) == 0)
			goto set_value;
	}
	
	// Now we must check the extensions
	VarCacheExtended *ext = cache->extended;
    while (ext) {
        if (strcasecmp(key, ext->name->str) == 0) {
            // Drop old value
            strpool_decref(ext->value);
            
            if (!value)
                return false;
            
            // Set new value
            pstr = strpool_get(vpool, value, strlen(value));
            if (!pstr)
                return false;
            ext->value = pstr;
            return true;
        }
        ext = ext->next;
    }
    
    if (!value)
        return false;
    
    // Build a new extended entry
    ext = malloc(sizeof(VarCacheExtended));
    
    pstr = strpool_get(vpool, value, strlen(value));
    if (!pstr) {
        free(ext);
        return false;
    }
    ext->value = pstr;
    
    pstr = strpool_get(vpool, key, strlen(key));
    if (!pstr) {
        strpool_decref(ext->value);
        free(ext);
        return false;
    }
    ext->name = pstr;
    
    // prepend in the linked list
    ext->next = cache->extended;
    cache->extended = ext;
    
    return true;

set_value:
	/* drop old value */
	strpool_decref(cache->var_list[lk->idx]);
	cache->var_list[lk->idx] = NULL;

	/* NULL value? */
	if (!value)
		return false;

	/* set new value */
	pstr = strpool_get(vpool, value, strlen(value));
	if (!pstr)
		return false;
	cache->var_list[lk->idx] = pstr;
	return true;
}

static int apply_var(PktBuf *pkt, const char *key,
		     const struct PStr *cval,
		     const struct PStr *sval)
{
	char buf[128];
	char qbuf[128];
	unsigned len;

	/* if unset, skip */
	if (!cval || !sval || !*cval->str)
		return 0;

	/* if equal, skip */
	if (cval == sval)
		return 0;

	/* ignore case difference */
	if (strcasecmp(cval->str, sval->str) == 0)
		return 0;

	/* the string may have been taken from startup pkt */
	if (!pg_quote_literal(qbuf, cval->str, sizeof(qbuf)))
		return 0;

	/* add SET statement to packet */
	len = snprintf(buf, sizeof(buf), "SET %s=%s;", key, qbuf);
	if (len < sizeof(buf)) {
		pktbuf_put_bytes(pkt, buf, len);
		return 1;
	} else {
		log_warning("got too long value, skipping");
		return 0;
	}
}

bool varcache_apply(PgSocket *server, PgSocket *client, bool *changes_p)
{
	int changes = 0;
	struct PStr *cval, *sval;
	const struct var_lookup *lk;
	int sql_ofs;
	struct PktBuf *pkt = pktbuf_temp();
    VarCacheExtended *cext;
    VarCacheExtended *sext;

	pktbuf_start_packet(pkt, 'Q');

	/* grab query position inside pkt */
	sql_ofs = pktbuf_written(pkt);

	for (lk = lookup; lk->name; lk++) {
		sval = get_value(&server->vars, lk);
		cval = get_value(&client->vars, lk);
		changes += apply_var(pkt, lk->name, cval, sval);
	}
	
	// Assume that both have been synchronized properly ? This seems risky
	sext = server->vars.extended;
    while (sext) {
        cext = client->vars.extended;
        while (cext) {
            if (strcasecmp(cext->name->str, sext->name->str) == 0) {
                changes += apply_var(pkt, cext->name->str, cext->value, sext->value);
                break;
            }
            cext = cext->next;
        }
        sext = sext->next;
    }

	*changes_p = changes > 0;
	if (!changes)
		return true;

	pktbuf_put_char(pkt, 0);
	pktbuf_finish_packet(pkt);

	slog_info(server, "varcache_apply: %s", pkt->buf + sql_ofs);
	return pktbuf_send_immediate(pkt, server);
}

void varcache_fill_unset(VarCache *src, PgSocket *dst)
{
	struct PStr *srcval, *dstval;
	const struct var_lookup *lk;
	for (lk = lookup; lk->name; lk++) {
		srcval = src->var_list[lk->idx];
		dstval = dst->vars.var_list[lk->idx];
		if (!dstval) {
			strpool_incref(srcval);
			dst->vars.var_list[lk->idx] = srcval;
		}
	}
	// extensions are not used here since they are not parameters
}

void varcache_clean(VarCache *cache)
{
	int i;
    VarCacheExtended *next;
	for (i = 0; i < NumVars; i++) {
		strpool_decref(cache->var_list[i]);
		cache->var_list[i] = NULL;
	}
	while (cache->extended) {
        strpool_decref(cache->extended->name);
        strpool_decref(cache->extended->value);
        next = cache->extended->next;
        free(cache->extended);
        cache->extended = next;
    }
}

void varcache_add_params(PktBuf *pkt, VarCache *vars)
{
	struct PStr *val;
	const struct var_lookup *lk;
	for (lk = lookup; lk->name; lk++) {
		val = vars->var_list[lk->idx];
		if (val)
			pktbuf_write_ParameterStatus(pkt, lk->name, val->str);
	}
	// Extended vars are not parameters
}

void varcache_deinit(void)
{
	strpool_free(vpool);
	vpool = NULL;
}
