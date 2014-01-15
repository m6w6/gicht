#include "gicht.h"

#include "gicht/dbuf.h"

dbuf_t *dbuf_init(dbuf_t *dbuf, size_t blk)
{
	if (dbuf) {
		memset(dbuf, 0, sizeof(*dbuf));
	} else {
		dbuf = calloc(1, sizeof(*dbuf));
	}

	return dbuf;
}

void dbuf_dtor(dbuf_t *dbuf)
{
	if (dbuf) {
		if (dbuf->buf) {
			free(dbuf->buf);
			dbuf->buf = NULL;
		}
	}
}

void dbuf_free(dbuf_t **dbuf)
{
	dbuf_dtor(*dbuf);
	FREEPTR(dbuf);
}

int dbuf_add(dbuf_t *dbuf, const char *str, size_t len)
{
	if (dbuf->mem < dbuf->len + len) {
		char *ptr;
		size_t blk = dbuf->blk ? dbuf->blk : DBUF_BLK;
		size_t mem = dbuf->mem + blk;

		while (mem < dbuf->len + len) {
			mem += blk;
		}
		ptr = realloc(dbuf->buf, mem);
		if (!ptr) {
			return ENOMEM;
		}
		dbuf->buf = ptr;
		dbuf->mem = mem;
	}

	memcpy(dbuf->buf + dbuf->len, str, len);
	dbuf->len += len;
	return 0;
}

void dbuf_cut(dbuf_t *dbuf, size_t cut)
{
	if (cut > dbuf->len) {
		cut = dbuf->len;
	}
	memmove(dbuf->buf, dbuf->buf + cut, dbuf->len - cut);
	dbuf->len -= cut;
}

bool dbuf_get(dbuf_t *dbuf, size_t len, char **str)
{
	if (dbuf->len < len) {
		return false;
	}

	if (len > dbuf->len / 2) {
		size_t blk = dbuf->blk ? dbuf->blk : DBUF_BLK;
		size_t mem = blk;
		char *ptr;

		while (mem < dbuf->len - len) {
			mem += blk;
		}
		ptr = malloc(mem);
		if (!ptr) {
			return ENOMEM;
		}

		memcpy(ptr, dbuf->buf + len, dbuf->len - len);
		*str = dbuf->buf;
		dbuf->buf = ptr;
		dbuf->mem = mem;
		dbuf->len = dbuf->len - len;
	} else {
		*str = malloc(len);
		memcpy(*str, dbuf->buf, len);
		dbuf_cut(dbuf, len);
	}

	return true;
}

/*
 * vim: set noet sw=4 ts=4
 */
