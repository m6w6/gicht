#include "gicht.h"
#include "gicht/dbuf.h"

#include <leveldb/c.h>
#include <math.h>

static char *const leveldb_options[] = {
		"leveldb_root",
		"leveldb_skew",
		"leveldb_force_verify_checksums",
		"leveldb_force_fill_cache",
		"leveldb_force_sync",
		NULL
};

typedef struct db db_t;
typedef struct db_options db_options_t;
typedef struct db_instance db_instance_t;

#define UNSET     (0xf)
#define FORCE_DEF (0x3)
#define FORCE_NOT (0x0)
#define FORCE_YES (0x1)

struct db_options {
	char *root;
	unsigned skew:2;
	unsigned force_verify_checksums:2;
	unsigned force_fill_cache:2;
	unsigned force_sync:2;
};

struct db_instance {
	leveldb_t *db;
	leveldb_options_t *opts;
	leveldb_readoptions_t *ro;
	leveldb_writeoptions_t *wo;
	leveldb_cache_t *cache;
	pthread_rwlock_t lock;
};

struct db {
	db_options_t options;
	db_instance_t **dbs;
	pthread_mutex_t mutex;
};

#define SKEW(s) (1<<(8*(s)))
#define SKEW_SIZE(s) (sizeof(db_instance_t *) * SKEW(s))

typedef struct db_request db_request_t;
typedef struct db_response db_response_t;

typedef enum e_db_parse {
	EP_SUCCESS,
	EP_COMPLETE,
	EP_NOMEM,
	EP_NAV,
	EP_NAC
} e_db_parse_t;

typedef enum db_version {
	VER_NAV = -1,
	VER_0 = 0,
	VER_EOV
} db_version_t;

typedef enum db_command {
	CMD_NAC = -1,
	CMD_NOP = 0,
	CMD_GET,
	CMD_PUT,
	CMD_EOC
} db_command_t;

typedef enum db_result {
	RES_NAR = -1,
	RES_OK = 0,
	RES_ERR,
	RES_EOR
} db_result_t;

#define FLAG_NONE           -1
#define FLAG_READ_VERIFIED 0x1
#define FLAG_READ_NOCACHE  0x2
#define FLAG_WRITE_SYNC    0x4

typedef int (*packer)(void *p, const char *str, size_t len);

uint64_t unpack(const char *str, size_t len)
{
	uint64_t i = 0, u = 0;

	for (i = 0; i < len; ++i) {
		u |= (str[i] << ((len - i) * 8));
	}

	return u;
}

int pack(uint64_t u, size_t len, packer packer, void *p)
{
	uint8_t i, c[8];

	for (i = 0; i < len; ++i) {
		c[i] = (u >> ((len - i) * 8)) & UINT8_MAX;
	}

	return packer(p, (const char *) c, len);
}

/**
 * Response:
 * =========
 *
 * # 1 byte API version
 * -
 * #### 4 byte Command
 * -
 * #### 4 byte Result type
 * - optional:
 * ######## 8 byte Value length
 * -
 * #* Value length byte Value data
 */
struct db_response {
	db_version_t version;
	db_command_t command;
	db_result_t result;
	dbuf_t hdr, val;
};

/*
 * Request:
 * =======
 *
 * # 1 byte API version
 * -
 * #### 4 byte Command
 * -
 * ######## 8 byte Flags
 * -
 * ######## 8 byte Key length
 * -
 * #* Key length byte Key data
 * - optional:
 * ######## 8 byte Value length
 * -
 * #* Value length byte Value data
 */
struct db_request {
	db_version_t version;
	db_command_t command;
	int64_t flags;
	dbuf_t buf;
	dbuf_t key;
	dbuf_t val;
	db_response_t res;
};

static void  db_request_dtor(db_request_t *request)
{
	if (request) {
		dbuf_dtor(&request->buf);
		dbuf_dtor(&request->key);
		dbuf_dtor(&request->val);
		dbuf_dtor(&request->res.hdr);
		dbuf_dtor(&request->res.val);
	}
}

static void db_request_free(db_request_t **request)
{
	db_request_dtor(*request);
	FREEPTR(request);
}

static db_request_t *db_request_init(context_t *context)
{
	db_request_t *request = calloc(1, sizeof(*request));

	if (request) {
		if (context) {
			context->data = request;
			context->dtor = (context_data_dtor) db_request_free;
		}

		request->version = VER_NAV;
		request->command = CMD_NAC;
		request->flags = FLAG_NONE;
		request->buf.blk = 0x100;
	}

	return request;
}

static e_db_parse_t db_request_parse(db_request_t *request, const char *buf, size_t len)
{
	size_t cut = 0;

	dbuf_add(&request->buf, buf, len);

	if (request->version == VER_NAV && request->buf.len >= 1) {
		request->version = unpack(request->buf.buf, 1);
		if (request->version <= VER_NAV || request->version >= VER_EOV) {
			return EP_NAV;
		}
		cut += 1;
	}
	if (request->command == CMD_NAC && request->buf.len >= cut + 4) {
		request->command = unpack(request->buf.buf + cut, 4);
		if (request->command <= CMD_NAC || request->command > CMD_EOC) {
			return EP_NAC;
		}
		cut += 4;
	}
	if (request->flags == FLAG_NONE && request->buf.len >= cut + 8) {
		request->flags = unpack(request->buf.buf + cut, 8);
		cut += 8;
	}
	if (!request->key.len && request->buf.len >= cut + 8) {
		request->key.len = unpack(request->buf.buf + cut, 8);
		cut += 8;
	}

	/* ok, fine */
	dbuf_cut(&request->buf, cut);
	cut = 0;

	if (!request->key.buf && request->key.len && request->buf.len >= request->key.len) {
		if (dbuf_get(&request->buf, request->key.len, &request->key.buf)) {
			switch (request->command) {
			case CMD_GET:
				return EP_COMPLETE;
			default:
				break;
			}
		}
	}

	if (!request->val.len && request->key.buf && request->buf.len >= 8) {
		request->val.len = unpack(request->buf.buf + cut, 8);
		cut += 8;
	}

	dbuf_cut(&request->buf, cut);
	cut = 0;

	if (!request->val.buf && request->val.len && request->buf.len >= request->val.len) {
		if (dbuf_get(&request->buf, request->val.len, &request->val.buf)) {
			return EP_COMPLETE;
		}
	}

	return EP_SUCCESS;
}

static void db_result_clear(db_request_t *request)
{
	dbuf_t *buffer;

	dbuf_dtor(&request->res.hdr);
	dbuf_dtor(&request->res.val);

	request->res.version = VER_NAV;
	request->res.command = CMD_NAC;
	request->res.result = RES_NAR;
}

static void db_result_build(db_request_t *request, char *err)
{
	dbuf_t tmp;

	db_result_clear(request);

	request->res.version = request->version;
	request->res.command = request->command;
	request->res.result  = err ? RES_ERR : RES_OK;

	pack(request->res.version, 1, (packer) dbuf_add, &request->res.hdr);
	pack(request->res.command, 4, (packer) dbuf_add, &request->res.hdr);
	pack(request->res.result, 4, (packer) dbuf_add, &request->res.hdr);

	if (err) {
		size_t errlen = strlen(err);

		pack(errlen, 8, (packer) dbuf_add, &request->res.hdr);
		dbuf_add(&request->res.val, err, errlen);
	} else {
		pack(request->val.len, 8, (packer) dbuf_add, &request->res.hdr);

		/* transfer request.val */
		memcpy(&tmp, &request->res.val, sizeof(request->res.val));
		memcpy(&request->res.val, &request->val, sizeof(request->val));
		memcpy(&request->val, &tmp, sizeof(tmp));
	}
}

static void db_request_reset(db_request_t *request, bool resultize, char *err)
{
	if (resultize) {
		db_result_build(request, err);
	} else {
		if (err) {
			free(err);
		}
		db_result_clear(request);
	}

	request->buf.len = 0;
	request->key.len = 0;
	request->val.len = 0;

	request->version = VER_NAV;
	request->command = CMD_NAC;
	request->flags = FLAG_NONE;
}

static void db_inst_free(db_instance_t **inst)
{
	if (*inst) {
		if ((*inst)->db) {
			leveldb_close((*inst)->db);
		}
		leveldb_options_destroy((*inst)->opts);
		leveldb_readoptions_destroy((*inst)->ro);
		leveldb_writeoptions_destroy((*inst)->wo);
		pthread_rwlock_destroy(&(*inst)->lock);
		FREEPTR(inst);
	}
}

static int db_inst_create(db_t *db, int slot, char **err)
{
	int rc;
	db_instance_t *inst;
	char name[FILENAME_MAX] = {0};

	inst = calloc(1, sizeof(*inst));
	if (!inst) {
		return ENOMEM;
	}

	snprintf(name, sizeof(name)-1, "%s/%09d.ldb", db->options.root, slot);

	inst->opts = leveldb_options_create();
	leveldb_options_set_create_if_missing(inst->opts, 1);
	/* FIXME implement options */
	inst->ro = leveldb_readoptions_create();
	leveldb_readoptions_set_fill_cache(inst->ro,
			db->options.force_fill_cache == FORCE_DEF ? 1 :
			db->options.force_fill_cache);
	leveldb_readoptions_set_verify_checksums(inst->ro,
			db->options.force_verify_checksums == FORCE_DEF ? 1 :
			db->options.force_verify_checksums);

	inst->wo = leveldb_writeoptions_create();
	leveldb_writeoptions_set_sync(inst->wo,
			db->options.force_sync == FORCE_DEF ? 0 :
			db->options.force_sync);

	rc = pthread_rwlock_init(&inst->lock, NULL);
	if (!rc) {
		rc = pthread_mutex_lock(&db->mutex);
		if (!rc) {
			if (db->dbs[slot]) {
				/* someone else was faster */
				db_inst_free(&inst);
			} else {
				inst->db = leveldb_open(inst->opts, name, err);
				if (inst->db) {
					db->dbs[slot] = inst;
				}
			}
		}
		pthread_mutex_unlock(&db->mutex);
	}

	if (rc) {
		db_inst_free(&inst);
	}

	return rc;
}


static uint32_t db_inst_slot(db_t *db, const dbuf_t *key)
{
	uint32_t slot;

	switch (db->options.skew) {
	default:
	case 0:
		slot = 0;
		break;
	case 1:
		slot = *key->buf;
		break;
	case 2:
	case 3:
		slot = unpack(key->buf, MIN(key->len, db->options.skew));
		break;
	}

	return slot;
}

static db_instance_t *db_inst_acquire(db_t *db, const dbuf_t *key, bool write)
{
	db_instance_t *inst = NULL;
	int rc, slot = db_inst_slot(db, key);
	char *err = NULL;

	if (db->dbs[slot]) {
		inst = db->dbs[slot];
	} else {
		rc = db_inst_create(db, slot, &err);
		if (!rc) {
			inst = db->dbs[slot];
		} else {
			/* err */
		}
	}

	if (inst) {
		if (write) {
			pthread_rwlock_wrlock(&inst->lock);
		} else {
			pthread_rwlock_rdlock(&inst->lock);
		}

	}

	return inst;
}

static void db_inst_release(db_t *db, db_instance_t *inst)
{
	pthread_rwlock_unlock(&inst->lock);
}

static void db_exec_get(db_t *db, db_request_t *request)
{
	db_instance_t *inst;
	char *err = NULL;

	inst = db_inst_acquire(db, &request->key, false);
	request->val.buf = leveldb_get(inst->db, inst->ro, request->key.buf, request->key.len, &request->val.len, &err);
	db_inst_release(db, inst);

	db_request_reset(request, true, err);
}

static void db_exec_put(db_t *db, db_request_t *request)
{
	db_instance_t *inst;
	char *err = NULL;

	inst = db_inst_acquire(db, &request->key, true);
	leveldb_put(inst->db, inst->wo, request->key.buf, request->key.len, request->val.buf, request->val.len, &err);
	db_inst_release(db, inst);
	db_request_reset(request, true, err);
}

static void db_exec(db_t *db, db_request_t *request)
{
	switch (request->command) {
	case CMD_GET:
		db_exec_get(db, request);
		break;

	case CMD_PUT:
		db_exec_put(db, request);
		break;

	default:
		break;
	}
}

static void db_opts(db_options_t *db_options, chash_t *options)
{
	char *optstr;
	int optint;

	if ((optstr = chash_get(options, "leveldb_root"))) {
		db_options->root = strdup(optstr);
	} else {
		db_options->root = strdup("tmp");
	}
	mkdir(db_options->root, 0750);

	if ((optstr = chash_get(options, "leveldb_skew"))) {
		db_options->skew = atoi(optstr) & 0x3; /* 0-3 */
	} else {
		db_options->skew = 0;
	}

	if ((optstr = chash_get(options, "leveldb_force_verify_checksum"))) {
		optint = atoi(optstr);
	} else {
		optint = -1;
	}
	switch(optint) {
	case -1: db_options->force_verify_checksums = FORCE_DEF; break;
	case 0:  db_options->force_verify_checksums = FORCE_NOT; break;
	default: db_options->force_verify_checksums = FORCE_YES; break;
	}

	if ((optstr = chash_get(options, "leveldb_force_fill_cache"))) {
		optint = atoi(optstr);
	} else {
		optint = -1;
	}
	switch(optint) {
	case -1: db_options->force_fill_cache = FORCE_DEF; break;
	case 0:  db_options->force_fill_cache = FORCE_NOT; break;
	default: db_options->force_fill_cache = FORCE_YES; break;
	}

	if ((optstr = chash_get(options, "leveldb_force_sync"))) {
		optint = atoi(optstr);
	} else {
		optint = -1;
	}
	switch(optint) {
	case -1: db_options->force_sync = FORCE_DEF; break;
	case 0:  db_options->force_sync = FORCE_NOT; break;
	default: db_options->force_sync = FORCE_YES; break;
	}
}

static bool db_init(module_t *module, chash_t *options, gichtd_t *gicht)
{
	db_t *db;
	size_t skew;
	db_options_t db_options;

	db_opts(&db_options, options);
	skew = SKEW_SIZE(db_options.skew);
	db = calloc(1, sizeof(*db) + skew);

	if (!db) {
		return ENOMEM;
	}
	db->options = db_options;
	db->dbs = (db_instance_t **) (((char *) db) + sizeof(*db));
	pthread_mutex_init(&db->mutex, NULL);

	module->context.data = db;
	return true;
}

static void db_dtor(module_t *module)
{
	db_t *db = module->context.data;
	size_t i;

	for (i = 0; i < SKEW(db->options.skew); ++i) {
		if (db->dbs[i]) {
			db_inst_free(&db->dbs[i]);
		}
	}

	pthread_mutex_destroy(&db->mutex);
	free(db->options.root);
	free(db);
}

#if 0

int db_read(module_t *module, ev_loop *ev, module_io_t *mio)
{
	char buf[0x100];
	ssize_t len = sizeof(buf);

	switch (module_reader(ev, mio, buf, &len, 0)) {
	case MIO_SUCCESS:
		if (len > 0) {
			/* if we have a complete command, go fire */
			switch (db_request_parse(&mio->current.context, buf, len)) {
			case EP_COMPLETE:
				db_exec(module->context.data, &mio->current.context);
				return EV_READ|EV_WRITE;

			default:
				return -1;
			case EP_SUCCESS:
				break;
			}
		}
		/* no break */
	case MIO_AGAIN:
		return 0;
	case MIO_ERROR:
		return -1;
	}
}

int db_write(module_t *module, ev_loop *ev, module_io_t *mio)
{
	db_request_t *request = mio->current.context.data;
	dbuf_t *dbuf;
	size_t written;

	if (!request) {
		return EV_READ;
	}
	switch (request->res.result) {
	case RES_ERR:
	case RES_OK:
		break;
	default:
		return EV_READ;
	}

	/* write the header */
	dbuf = &request->res.hdr;
	if (dbuf->len) {
		switch (module_writer(ev, mio, dbuf->buf, dbuf->len, MSG_MORE, &written)) {
		case MIO_SUCCESS:
			dbuf->len = 0;
			break;

		case MIO_AGAIN:
			if (written) {
				dbuf_cut(dbuf, written);
			}
			return 0;

		case MIO_ERROR:
			return -1;
		}
	}

	/* write the value */
	dbuf = &request->res.val;
	if (!dbuf->len) {
		return EV_READ;
	}

	switch (module_writer(ev, mio, dbuf->buf, dbuf->len, 0, &written)) {
	case MIO_SUCCESS:
		dbuf->len = 0;
		return EV_READ;

	case MIO_AGAIN:
		if (written) {
			dbuf_cut(dbuf, written);
		}
		return 0;

	case MIO_ERROR:
		return -1;
	}
}
#endif

static void db_event(ev_loop *ev, ev_io *io, int revents)
{
	module_io_t *mio = (module_io_t *) io;
	db_request_t *request = chash_get(&mio->contexts, "leveldb");

	if (!request) {
		return;
	}

	if (revents & EV_READ) {
		char buf[0x1000];
		ssize_t len = sizeof(buf);
		int wevents;

		wevents = mio->read(ev, mio, buf, &len, 0);
		if (!module_io_reschedule(ev, io, wevents)) {
			return;
		}

		if (len) {


			/* if we have a complete command, go fire */
			switch (db_request_parse(request, buf, len)) {
			case EP_COMPLETE:
				db_exec(mio->module->context.data, request);
				module_io_reschedule(ev, io, EV_READ|EV_WRITE);
				break;

			default:
				module_io_reschedule(ev, io, -1);
				/* no break */

			case EP_SUCCESS:
				break;
			}
		}
	}

	if (revents & EV_WRITE) {
		int wevents;
		dbuf_t *dbuf;
		size_t written;

		switch (request->res.result) {
		case RES_ERR:
		case RES_OK:
			break;

		default:
			module_io_reschedule(ev, io, EV_READ);
			return;
		}

		/* write the header */
		dbuf = &request->res.hdr;
		if (dbuf->len) {
			wevents = mio->write(ev, mio, dbuf->buf, dbuf->len, &written, MSG_MORE);
			if (!module_io_reschedule(ev, io, wevents)) {
				return;
			}
			dbuf_cut(dbuf, written);
			if (dbuf->len) {
				module_io_reschedule(ev, io, wevents|EV_WRITE);
				return;
			}
		}

		/* write the value */
		dbuf = &request->res.val;
		if (!dbuf->len) {
			module_io_reschedule(ev, io, EV_READ);
			return;
		}

		wevents = mio->write(ev, mio, dbuf->buf, dbuf->len, &written, 0);
		if (!module_io_reschedule(ev, io, wevents)) {
			return;
		}
		dbuf_cut(dbuf, written);
		if (dbuf->len) {
			module_io_reschedule(ev, io, wevents|EV_WRITE);
		}
	}
}

static module_io_t *db_work(module_fd_t *client)
{
	module_io_t *mio;
	context_t context = {db_request_init(NULL), (context_data_dtor) db_request_free};

	mio = module_io_init(NULL, client);
	if (mio) {
		ev_io_init(&mio->io, db_event, client->fd, EV_READ);
	}
	chash_add(&mio->contexts, "leveldb", &context);

	return mio;
}


static module_t leveldb_module = {
		0,
		GICHT_VERSION(0,0,1),
		"leveldb",
		{NULL, NULL},
		leveldb_options,
		db_init,
		db_dtor,
		db_work,
		NULL
};

module_t *gicht_get_module()
{
	return &leveldb_module;
}

/*
 * vim: set noet sw=4 ts=4
 */
