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

#ifndef GICHT_MODULE_H_
#define GICHT_MODULE_H_

typedef struct module module_t;
typedef struct module_io module_io_t;
typedef struct module_fd module_fd_t;

typedef bool (*module_init)(module_t *module, chash_t *options, gichtd_t *gicht);
typedef void (*module_dtor)(module_t *module);
typedef module_io_t *(*module_work)(module_fd_t *client);
typedef module_t *(*module_wrap)(module_t *wrapper, module_t *wrapped);

typedef int (*module_evio)(module_io_t *mio);
typedef int (*module_read)(module_t *module, ev_loop *ev, module_io_t *mio);
typedef int (*module_write)(module_t *module, ev_loop *ev, module_io_t *mio);
typedef bool (*module_accept)(module_t *module, module_fd_t *client);

typedef enum e_mio {
	MIO_ERROR,
	MIO_AGAIN,
	MIO_SUCCESS
} e_mio_t;

typedef int (*module_io_read)(ev_loop *ev, module_io_t *mio, char *buf, ssize_t *len, int recv_flags);
typedef int (*module_io_write)(ev_loop *ev, module_io_t *mio, const char *buf, size_t len, size_t *written, int send_flags);

struct module_io {
	ev_io io;
	module_t *module;
	chash_t contexts;
	module_fd_t *client;
	module_io_read read;
	module_io_write write;
};

module_io_t *module_io_init(module_io_t *mio, module_fd_t *client);
void module_io_event(ev_loop *ev, ev_io *io, int revents);
bool module_io_reschedule(ev_loop *ev, ev_io *io, int nevents);
void module_io_dtor(module_io_t *mio);
void module_io_free(module_io_t **mio);

struct module_fd {
	int fd;
	module_t *module;
	thread_t *thread;
	context_t context;
	struct sockaddr_storage addr;
	socklen_t addr_len;
};

module_fd_t *module_fd_init(module_fd_t *mfd, module_t *module);
void module_fd_dtor(module_fd_t *mfd);
void module_fd_free(module_fd_t **mfd);

struct module {
	unsigned api;
	unsigned version;
	const char *name;
	context_t context;
	char *const *options;
	module_init init;
	module_dtor dtor;
	module_work work;
	module_wrap wrap;
};

module_t *module_load(gichtd_t *gicht, char *module_name);
chash_t *module_options(gichtd_t *gicht, char *const *options);
int module_reader(ev_loop *ev, module_io_t *mio, char *buf, ssize_t *len, int recv_flags);
int module_writer(ev_loop *ev, module_io_t *mio, const char *buf, size_t len, size_t *written, int send_flags);
module_io_t *module_worker(module_fd_t *client);

#endif

/*
 * vim: set noet sw=4 ts=4
 */
