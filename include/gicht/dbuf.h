#ifndef GICHT_DBUF_H_
#define GICHT_DBUF_H_

typedef struct dbuf dbuf_t;

struct dbuf {
	char *buf;
	size_t len;
	size_t mem;
	size_t blk;
};

#ifndef DBUF_BLK
#define DBUF_BLK 0x100
#endif

#define dbuf_new() dbuf_init(NULL, DBUF_BLK)
dbuf_t *dbuf_init(dbuf_t *dbuf, size_t blk);
void dbuf_dtor(dbuf_t *dbuf);
void dbuf_free(dbuf_t **dbuf);
int dbuf_add(dbuf_t *dbuf, const char *str, size_t len);
bool dbuf_get(dbuf_t *dbuf, size_t len, char **str);
void dbuf_cut(dbuf_t *dbuf, size_t cut);

#endif
