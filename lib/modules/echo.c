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

#include "gicht/lbuf.h"
#include <ctype.h>

typedef struct transform transform_t;

struct transform {
	char *name;
	void (*func)(char *buf, size_t len);
};

static void _reverse(char *buf, size_t len)
{
	size_t nel;

	for (nel = 0, --len; nel < len; --len, ++nel) {
		char x =  buf[nel];

		buf[nel] = buf[len-1];
		buf[len-1] = x;
	}
}

static void _uppercase(char *buf, size_t len)
{
	while (len--) {
		buf[len] = toupper((int) buf[len]);
	}
}

static void _lowercase(char *buf, size_t len)
{
	while (len--) {
		buf[len] = tolower((int) buf[len]);
	}
}

static const transform_t echo_tr[] = {
		{"reverse", _reverse},
		{"uppercase", _uppercase},
		{"lowercase", _lowercase}
};

static char *const echo_options[] = {
		"echo_tr",
		NULL
};

static int _cmp(const void *a, const void *b)
{
	return strcmp(a, ((transform_t *) b)->name);
}

static bool echo_init(module_t *module, chash_t *options, gichtd_t *gicht)
{
	int i;
	char *tr_name;
	transform_t *tr_func;

	if ((tr_name = chash_get(options, "echo_tr"))) {
		size_t nel = sizeof(echo_tr)/sizeof(transform_t);

		tr_func = lfind(tr_name, (const void *) echo_tr, &nel, sizeof(*tr_func), _cmp);
		if (tr_func) {
			module->context.data = tr_func;
		}
	}
	return true;
}

static void echo_event(ev_loop *ev, ev_io *io, int revents)
{
	module_io_t *mio = (module_io_t *) io;
	lbuf_t *lbuf = NULL;

	if (revents & EV_READ) {
		char buf[0x1000];
		ssize_t len = sizeof(buf);
		int wevents;

		wevents = mio->read(ev, mio, buf, &len, 0);
		if (!module_io_reschedule(ev, io, wevents)) {
			return;
		}

		if (len) {
			lbuf = chash_get(&mio->contexts, "echo");

			if (lbuf) {
				bool lf = false;

				if (!lbuf_add(lbuf, buf, len, &lf)) {
					if (lf) {
						if (!module_io_reschedule(ev, io, EV_READ|EV_WRITE)) {
							return;
						}
					}
				} else {
					module_io_reschedule(ev, &mio->io, -1);
				}
			}
		}
	}

	if (revents & EV_WRITE) {
		int wevents;
		char *line;
		size_t len, written;

		if (!lbuf) {
			lbuf = chash_get(&mio->contexts, "echo");
		}
		if (lbuf) {
			char *line;

			do {
				written = len = 0;
				line = lbuf_get(lbuf, &len);

				if (line) {
					wevents = mio->write(ev, mio, line, len, &written, 0);
					if (!module_io_reschedule(ev, &mio->io, wevents)) {
						return;
					}
					lbuf_cut(lbuf, written);
				} else {
					module_io_reschedule(ev, &mio->io, EV_READ);
				}
			} while (line);
		}
	}
}

static module_io_t *echo_work(module_fd_t *client)
{
	module_io_t *mio;
	context_t context = {lbuf_init(NULL), (context_data_dtor) lbuf_free};

	mio = module_io_init(NULL, client);
	if (mio) {
		ev_io_init(&mio->io, echo_event, client->fd, EV_READ);
	}
	chash_add(&mio->contexts, "echo", &context);

	return mio;
}

static module_t echo_module = {
		0,
		GICHT_VERSION(0,0,1),
		"echo",
		{NULL, NULL},
		echo_options,
		echo_init,
		NULL,
		echo_work,
		NULL
};

module_t *gicht_get_module()
{
	return &echo_module;
}

/*
 * vim: set noet sw=4 ts=4
 */
