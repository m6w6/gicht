#include "gicht.h"

#if HAVE_LIBSSL

#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct ssl ssl_t;

struct ssl {
	module_t *wrapped;
	char *cert;
	char *key_dsa;
	char *key_rsa;
};

static char *const ssl_options[] = {
		"ssl_cert",
		"ssl_key_rsa",
		"ssl_key_dsa",
		NULL
};

static int ssl_io(SSL *con, int rc)
{
	switch (SSL_get_error(con, rc)) {
	case SSL_ERROR_NONE:
		return 0;
	case SSL_ERROR_WANT_READ:
		return EV_READ;
	case SSL_ERROR_WANT_WRITE:
		return EV_WRITE;
	default:
		return -1;
	}
}

static void ssl_errors(gichtd_t *gicht)
{
	long e;

	while ((e = ERR_get_error())) {
		gichtd_log(gicht, LOG_ERR, "ssl: %s (%s in %s)",
				ERR_reason_error_string(e),
				ERR_func_error_string(e),
				ERR_lib_error_string(e));
	}
}

static int ssl_reader(ev_loop *ev, module_io_t *mio, char *buf, ssize_t *len, int recv_flags)
{
	module_io_t *sio = chash_get(&mio->contexts, "sio");
	SSL *con = chash_get(&sio->contexts, "ssl");
	int read;

	read = SSL_read(con, buf, *len);
	switch (ssl_io(con, read)) {
	default:
	case -1:
		return -1;

	case 0:
		*len = read;
		return 0;

	case EV_READ:
		return EV_READ;

	case EV_WRITE:
		return EV_WRITE|EV_READ;
	}
}

static int ssl_writer(ev_loop *ev, module_io_t *mio, const char *buf, size_t len, size_t *written, int send_flags)
{
	module_io_t *sio = chash_get(&mio->contexts, "sio");
	SSL *con = chash_get(&sio->contexts, "ssl");
	int write;

	write = SSL_write(con, buf, len);
	switch (ssl_io(con, write)) {
	default:
	case -1:
		ssl_errors(((thread_t *) ev_userdata(ev))->gicht);
		return -1;

	case 0:
		*written = write;
		return 0;

	case EV_READ:
		return EV_READ;

	case EV_WRITE:
		return EV_WRITE|EV_READ;
	}
}

typedef struct CRYPTO_dynlock_value {
	pthread_rwlock_t rw;
} ssl_lock_t;

static ssl_lock_t *ssl_lock_init(const char *file, int line)
{
	ssl_lock_t *lock = calloc(1, sizeof(*lock));

	if (lock) {
		pthread_rwlock_init(&lock->rw, NULL);
	}

	return lock;
}

static void ssl_lock_lock(int mode, ssl_lock_t *lock, const char *file, int line)
{
	if (mode & CRYPTO_UNLOCK) {
		pthread_rwlock_unlock(&lock->rw);
	} else if (mode & CRYPTO_WRITE) {
		pthread_rwlock_wrlock(&lock->rw);
	} else {
		pthread_rwlock_rdlock(&lock->rw);
	}
}

static void ssl_lock_dtor(ssl_lock_t *lock, const char *file, int line)
{
	pthread_rwlock_destroy(&lock->rw);
	free(lock);
}

static void ssl_thread(CRYPTO_THREADID *id)
{
	CRYPTO_THREADID_set_numeric(id, pthread_self());
}

static SSL_CTX *ssl_init_ctx(gichtd_t *gicht, ssl_t *ssl)
{
	SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());

	gichtd_log(gicht, LOG_INFO, "ssl: new context: %p", ctx);

	if (ctx) {
		if (ssl->cert) {
			if (!SSL_CTX_use_certificate_chain_file(ctx, ssl->cert)) {
				gichtd_log(gicht, LOG_ERR,
						"ssl: Failed to use cerificate chain file: '%s'",
						ssl->cert);
			} else {
				do {
					if (ssl->key_dsa) {
						if (!SSL_CTX_use_PrivateKey_file(ctx, ssl->key_dsa,
								SSL_FILETYPE_PEM)) {
							gichtd_log(gicht, LOG_ERR,
									"ssl: Failed to use DSA PrivateKey PEM file:"
									" '%s'", ssl->key_dsa);
							break;
						}
					}
					if (ssl->key_rsa) {
						if (!SSL_CTX_use_RSAPrivateKey_file(ctx, ssl->key_rsa,
								SSL_FILETYPE_PEM)) {
							gichtd_log(gicht, LOG_ERR,
									"ssl: Failed to use RSA PrivateKey PEM file:"
									" '%s'", ssl->key_rsa);
							break;
						}
					}

					return ctx;
				} while(false);
			}
		}

		SSL_CTX_free(ctx);
	}

	return NULL;
}

static bool ssl_init(module_t *module, chash_t *options, gichtd_t *gicht)
{
	ssl_t *ssl;

	ssl = calloc(1, sizeof(*ssl));
	if (!ssl) {
		return false;
	}
	module->context.data = ssl;

	SSL_load_error_strings();
	SSL_library_init();

	CRYPTO_THREADID_set_callback(ssl_thread);
	CRYPTO_set_dynlock_create_callback(ssl_lock_init);
	CRYPTO_set_dynlock_lock_callback(ssl_lock_lock);
	CRYPTO_set_dynlock_destroy_callback(ssl_lock_dtor);

	if ((ssl->cert = chash_get(options, "ssl_cert"))) {
		ssl->cert = strdup(ssl->cert);
	}
	if ((ssl->key_dsa = chash_get(options, "ssl_key_dsa"))) {
		ssl->key_dsa = strdup(ssl->key_dsa);
	}
	if ((ssl->key_rsa = chash_get(options, "ssl_key_rsa"))) {
		ssl->key_rsa = strdup(ssl->key_rsa);
	}

	ssl_errors(gicht);

	return true;
}

static void ssl_dtor_ctx(void **ctx)
{
	SSL_CTX_free(*(SSL_CTX **) ctx);
}

static void ssl_dtor(module_t *module)
{
	ssl_t *ssl = module->context.data;

	if (ssl) {
		if (ssl->wrapped) {
			free(module);
		}

		free(ssl);
	}
}

static module_t *ssl_wrap(module_t *wrapper, module_t *wrapped)
{
	module_t *module = malloc(sizeof(*module));

	if (module) {
		memcpy(module, wrapper, sizeof(*module));
		((ssl_t *) module->context.data)->wrapped = wrapped;
	}

	return module;
}

static void ssl_event(ev_loop *ev, ev_io *io, int revents)
{
	int wevents;
	context_t context;
	module_io_t *mio = (module_io_t *) io;
	ssl_t *ssl = mio->module->context.data;
	SSL *con = chash_get(&mio->contexts, "ssl");

	wevents = ssl_io(con, SSL_accept(con));
	switch (wevents) {
	case 0:
		ev_io_stop(ev, io);
		context.data = io;
		context.dtor = (context_data_dtor) module_io_free;
		mio = ssl->wrapped->work(mio->client);
		chash_add(&mio->contexts, "sio", &context);
		mio->read = ssl_reader;
		mio->write = ssl_writer;
		ev_io_start(ev, &mio->io);
		break;

	case -1:
		module_io_reschedule(ev, io, -1);
		return;

	default:
		module_io_reschedule(ev, io, wevents);
		break;
	}
}

static void _dtor(void **p)
{
	SSL *con = *(SSL **) p;

	SSL_shutdown(con);
	SSL_free(con);

	*p = NULL;
}

static module_io_t *ssl_work(module_fd_t *mfd)
{
	ssl_t *ssl = mfd->module->context.data;
	module_io_t *mio = NULL;
	context_t context;
	BIO *buf;
	SSL *con;
	SSL_CTX *ctx;

	buf = BIO_new_socket(mfd->fd, BIO_NOCLOSE);
	if (buf) {
		ctx = chash_get(&mfd->thread->storage, "ssl_ctx");

		if (!ctx) {
			ctx = ssl_init_ctx(mfd->thread->gicht, ssl);
			if (ctx) {
				context_t data;

				data.data = ctx;
				data.dtor = ssl_dtor_ctx;
				chash_add(&mfd->thread->storage, "ssl_ctx", &data);
			}
		}
		if (ctx) {
			con = SSL_new(ctx);

			if (con) {
				int wevents;

				SSL_set_debug(con, 1);
				SSL_set_bio(con, buf, buf);

				wevents = ssl_io(con, SSL_accept(con));
				switch (wevents) {
				case -1:
					SSL_free(con);
					return NULL;

				case 0:
					wevents = EV_READ|EV_WRITE;
					/* no break */

				default:
					mio = module_io_init(NULL, mfd);
					if (mio) {
						ev_io_init(&mio->io, ssl_event, mfd->fd, wevents);

						context.data = con;
						context.dtor = _dtor;

						chash_add(&mio->contexts, "ssl", &context);
					}
					break;
				}
			}
		}
	}

	return mio;
}

static module_t ssl_module = {
		0,
		GICHT_VERSION(0, 0, 1),
		"ssl",
		{NULL, NULL},
		ssl_options,
		ssl_init,
		ssl_dtor,
		ssl_work,
		ssl_wrap
};

module_t *gicht_get_module()
{
	return &ssl_module;
}

#endif

/*
 * vim: set noet sw=4 ts=4
 */
