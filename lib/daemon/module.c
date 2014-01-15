/*/ GICHT

Copyright (c) 2013, Michael Wallner <mike@php.net>.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. /*/

#include "gicht.h"
#include "gicht/private/gichtd.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* FIXME there are other dl mechanisms than dlsym */

#ifdef NEED_USCORE
#define DLSYM(dl, sym, name) \
	*(void **) (&(sym)) = dlsym((dl), "_"(name))
#else
#define DLSYM(dl, sym, name) \
	*(void **) (&(sym)) = dlsym((dl), (name))
#endif

typedef struct module_dl module_dl_t;

struct module_dl {
	module_t *module;
	void *dl;
};

module_dl_t *module_dl_init(module_dl_t *mdl, module_t *module, void *dl)
{
	if (mdl) {
		memset(mdl, 0, sizeof(*mdl));
	} else {
		mdl = calloc(1, sizeof(*mdl));
	}

	if (mdl) {
		mdl->module = module;
		mdl->dl = dl;
	}

	return mdl;
}

static void module_dl_dtor(module_dl_t *mdl)
{
	if (mdl->module->dtor) {
		mdl->module->dtor(mdl->module);
	} else {
		context_dtor(&mdl->module->context);
	}

	if (mdl->dl) {
#if !DEBUG
		dlclose(mdl->dl);
#endif
	}
}

static void module_dl_free(module_dl_t **mdl)
{
	module_dl_dtor(*mdl);
	FREEPTR(mdl);
}

module_dl_t *_load(gichtd_t *gicht, const char *module_name, bool *init)
{
	void *dl;
	module_t *module;
	module_dl_t *mdl = NULL;
	char module_path[FILENAME_MAX] = {0};

	snprintf(module_path, sizeof(module_path) - 1, "%s/%s%s",
			gicht->options->moduledir, module_name, LT_MODULE_EXT);
	dl = dlopen(module_path, RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);

	if (!dl) {
		dl = dlopen(module_path, RTLD_NOW | RTLD_LOCAL);
		*init = true;
	}
	if (dl) {
		module_t *(*get_module)(void);

		DLSYM(dl, get_module, "gicht_get_module");
		if (get_module) {
			module = DL_CALL_FCT(get_module, ());
			if (module) {
				mdl = module_dl_init(NULL, module, dl);
			}
		}
	}

	if (mdl) {
		gichtd_log(gicht, LOG_INFO, "Loaded module '%s': '%s'", mdl->module->name, module_path);
	} else {
		gichtd_log(gicht, LOG_ERR, "Failed to load module %s: %s", module_path, dlerror());
	}

	return mdl;
}

static bool _init(gichtd_t *gicht, module_dl_t *mdl, module_t *mod, bool init)
{
	context_t module;

	if (init) {
		chash_t *options;

		options = module_options(gicht, mdl->module->options);
		if (!mdl->module->init(mdl->module, options, gicht)) {
			gichtd_log(gicht, LOG_ERR, "Failed to init module %s", mdl->module->name);
			chash_free(&options);
			return false;
		}
		chash_free(&options);
	}

	if (mod) {
		if (!mdl->module->wrap) {
			return false;
		} else {
			module_t *wrapper = mdl->module->wrap(mdl->module, mod);

			if (!wrapper) {
				gichtd_log(gicht, LOG_ERR, "Failed to wrap module %s+%s", mod->name,
						mdl->module->name);
				return false;
			} else {
				mdl->module = wrapper;
			}
		}
	}

	module.data = mdl;
	module.dtor = (context_data_dtor) module_dl_free;

	if (dllist_push(&gicht->modules, &module)) {
		return false;
	}

	return true;
}

module_t *module_load(gichtd_t *gicht, char *module_name)
{
	module_dl_t *mdl;
	module_t *mod = NULL;
	char *ptr;
	bool init = false;

	if (module_name) {
		do {
			ptr = strchr(module_name, '+');

			if (ptr) {
				*ptr = 0;
			}

			mdl = _load(gicht, module_name, &init);
			if (mdl) {
				if (!_init(gicht, mdl, mod, init)) {
					module_dl_free(&mdl);
					return NULL;
				}

				if (mdl) {
					mod = mdl->module;
				}
			}

			if (ptr) {
				module_name = ptr + 1;
				*ptr = '+';
			}
		} while (ptr && mdl);
	}
	return mod;
}

int module_reader(ev_loop *ev, module_io_t *mio, char *buf, ssize_t *len,
		int recv_flags)
{
	ssize_t buflen = *len;

	do {
		*len = recv(mio->io.fd, buf, buflen, MSG_NOSIGNAL | recv_flags);

		if (*len > 0) {
			return 0;
		}

		if (*len < 0) {
			switch (errno) {
			case EINTR:
				/* try again */
				continue;

			case EAGAIN:
				/* wait again */
				return 0;

			case ECONNRESET:
			case ENOTCONN:
			case ETIMEDOUT:
				gichtd_log(((thread_t *) ev_userdata(ev))->gicht, LOG_INFO,
						"read(): %s", strerror(errno));
				return -1;

			default:
				gichtd_log(((thread_t *) ev_userdata(ev))->gicht, LOG_ERR, "read(): %s", strerror(errno));
				return -1;
			}
		}
	} while(false);

	return -1;
}

int module_writer(ev_loop *ev, module_io_t *mio, const char *buf, size_t len,
		size_t *written, int send_flags)
{
	*written = 0;

	do {
		ssize_t wri = send(mio->io.fd, buf, len, MSG_NOSIGNAL | send_flags);

		if (wri > 0) {
			*written += wri;

			buf += wri;
			len -= wri;

			if (len) {
				continue;
			} else {
				return EV_READ;
			}
		}

		if (wri == -1) {
			switch (errno) {
			case EINTR:
				/* try again */
				continue;

			case EAGAIN:
				/* wait again */
				return 0;

			case ECONNRESET:
			case ENOTCONN:
			case ETIMEDOUT:
				gichtd_log(((thread_t *) ev_userdata(ev))->gicht, LOG_INFO, "read(): %s", strerror(errno));
				return -1;

			default:
				gichtd_log(((thread_t *) ev_userdata(ev))->gicht, LOG_ERR, "read(): %s", strerror(errno));
				return -1;
			}
		}
	} while(false);

	return -1;
}

chash_t *module_options(gichtd_t *gicht, char *const *options)
{
	chash_t *hash = chash_init(NULL, 64);

	if (gicht->options->options) {
		char *optkey, *optval, *optsav, *opttmp, *optstr;
		context_t optitem = {NULL, context_data_free};

		optstr = opttmp = strdup(gicht->options->options);

		while ((optkey = strtok_r(optstr, ",", &optsav))) {
			int index;

			optstr = NULL;
			if (0 > (index = getsubopt(&optkey, options, &optval))) {
				continue;
			}

			optitem.data = strdup(optval);
			chash_add(hash, options[index], &optitem);
		}
		free(opttmp);
	}

	return hash;
}

module_io_t *module_io_init(module_io_t *mio, module_fd_t *client)
{
	if (mio) {
		memset(mio, 0, sizeof(*mio));
	} else {
		mio = calloc(1, sizeof(*mio));
	}

	if (mio) {
		if (!chash_init(&mio->contexts, 8)) {
			FREEPTR(&mio);
		} else {
			mio->client = client;
			mio->module = client->module;
			mio->read = module_reader;
			mio->write = module_writer;
		}
	}

	return mio;
}

void module_io_dtor(module_io_t *io)
{
	if (io) {
		chash_dtor(&io->contexts);
	}
}

void module_io_free(module_io_t **io)
{
	module_io_dtor(*io);
	FREEPTR(io);
}

bool module_io_reschedule(ev_loop *ev, ev_io *io, int nevents)
{
	module_io_t *mio = (module_io_t *) io;

	if (nevents < 0) {
		ev_io_stop(ev, io);
		module_io_free(&mio);
		return false;
	}

	/* keep watching */
	if (nevents > 0) {
		/* change watched events */
		ev_io_stop(ev, io);
		ev_io_set(io, io->fd, nevents);
		ev_io_start(ev, io);
	}

	return true;
}

module_fd_t *module_fd_init(module_fd_t *mfd, module_t *module)
{
	if (mfd) {
		memset(mfd, 0, sizeof(*mfd));
	} else {
		mfd = calloc(1, sizeof(*mfd));
	}

	mfd->addr_len = sizeof(struct sockaddr_storage);
	mfd->module = module;

	return mfd;
}

void module_fd_dtor(module_fd_t *mfd)
{
	if (mfd && mfd->fd >= 0) {
		close(mfd->fd);
	}
}

void module_fd_free(module_fd_t **mfd)
{
	module_fd_dtor(*mfd);
	FREEPTR(mfd);
}

/*
 * vim: set noet
 */
