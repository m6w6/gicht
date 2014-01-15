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

typedef struct acceptor acceptor_t;

struct acceptor {
	ev_async wakeup;
	ev_loop *ev;
	dllist_t listeners;
};

#ifndef HAVE_ACCEPT4
static int accept4(int fd, void *addr, size_t *addr_len, int set_flags)
{
	int got_flags, sock = accept(fd, addr, addr_len);

	if (sock >= 0 && set_flags) {
		if ((got_flags = fcntl(sock, F_GETFL)) < 0) {
			close(sock);
			return -1;
		}
		if (fcntl(sock, F_SETFL, got_flags | set_flags) < 0) {
			close(sock);
			return -1;
		}
	}

	return sock;
}
#endif

static void _event(ev_loop *ev, ev_io *io, int revents)
{
	thread_t *thread = ev_userdata(ev);
	acceptor_t *acceptor = thread->context.data;
	module_io_t *mio = (module_io_t *) io;
	int rc;

	if (revents & EV_READ) {
		module_fd_t *client = module_fd_init(NULL, mio->module);

		client->fd = accept4(io->fd, (void *) &client->addr, &client->addr_len, SOCK_NONBLOCK);
		gichtd_log(thread->gicht, LOG_INFO, "Accepted client (fd=%d)", client->fd);

		if (client->fd >= 0) {
			if (!worker_work(gichtd_worker(thread->gicht), client)) {
				return;
			}
		}

		module_fd_free(&client);
	}
}

static void _wakeup(ev_loop *ev, ev_async *as, int revents)
{
	thread_t *thread = ev_userdata(ev);

	if ((revents & EV_ASYNC) && !gichtd_is_running(thread->gicht)) {
		ev_break(ev, EVBREAK_ONE);
	}
}

static void _start(acceptor_t *acceptor, module_t *module, int fd)
{
	module_io_t *io;
	module_fd_t *ls;

	ls = module_fd_init(NULL, module);
	if (ls) {
		ls->fd = fd;

		io = module_io_init(NULL, ls);
		if (io) {
			context_t context;

			context.data = io;
			context.dtor = (context_data_dtor) module_io_free;
			dllist_push(&acceptor->listeners, &context);

			context.data = ls;
			context.dtor = (context_data_dtor) module_fd_free;
			chash_add(&io->contexts, "fd_dtor", &context);

			ev_io_init((ev_io *)io, _event, fd, EV_READ);
			ev_io_start(acceptor->ev, &io->io);
		} else {
			module_fd_free(&ls);
		}
	}
}

static void _announce(gichtd_t *gicht, const char *listen_spec, struct addrinfo *resptr,
		const char *modules)
{
	char *ptr, buf[NI_MAXHOST + NI_MAXSERV + 2] = {0};

	if (0 == getnameinfo(resptr->ai_addr, resptr->ai_addrlen,
			buf + NI_MAXSERV + 1, sizeof(buf) - NI_MAXSERV - 1,
			buf, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV)) {
		gichtd_log(gicht, LOG_INFO, "Listening to %s on %s:%s",
				modules, buf + NI_MAXSERV + 1, buf);
	} else {
		gichtd_log(gicht, LOG_INFO, "Listening on %s", listen_spec);
	}

}

static int _address(const char *listen_spec, struct addrinfo **result,
		char **mod_ptr)
{
	char *host_ptr = NULL;
	const char *host, *port;
	struct addrinfo hints = {0};
	int rc;

	if ((host = strchr(listen_spec, '@'))) {
		*mod_ptr = strndup(listen_spec, host++ - listen_spec);
	} else {
		host = listen_spec;
	}
	if ((port = strrchr(host, ':'))) {
		host_ptr = strndup(host, port++ - host);
	}

	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags    = AI_PASSIVE;

	rc = getaddrinfo(host_ptr ? host_ptr : host, port, &hints, result);

	if (host_ptr) {
		free(host_ptr);
	}

	return rc;
}

static int _socket(gichtd_t *gicht, const char *listen_spec, struct addrinfo *resptr, int *fd)
{
	int rc, yes = 1;

	*fd = socket(resptr->ai_family, resptr->ai_socktype, resptr->ai_protocol);
	if (*fd < 0) {
		gichtd_log(gicht, LOG_ERR, "Failed to create socket for %s: %s", listen_spec, strerror(errno));
		return errno;
	}

	setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

	rc = bind(*fd, resptr->ai_addr, resptr->ai_addrlen);
	if (rc) {
		close(*fd);
		gichtd_log(gicht, LOG_ERR, "Failed to bind socket to %s: %s", listen_spec, strerror(errno));
		return rc;
	}

	rc = listen(*fd, SOMAXCONN);
	if (rc) {
		close(*fd);
		gichtd_log(gicht, LOG_ERR, "Failed to listen on socket on %s: %s", listen_spec, strerror(errno));
		return rc;
	}

	return 0;
}

static unsigned _listen(acceptor_t *acceptor, gichtd_t *gicht)
{
	module_t *module;
	module_io_t *io = NULL;
	int rc, fd, yes = 1;
	char *mod_ptr = NULL;
	const char *mod, **lptr;
	struct addrinfo *result, *resptr;

	/*
	 * a single listen spec looks like: module[+module[...]]@host:port
	 */
	for (lptr = gicht->options->listen; *lptr; ++lptr) {
		rc = _address(*lptr, &result, &mod_ptr);
		if (rc) {
			gichtd_log(gicht, LOG_ERR, "Failed to resolve server host: %s", gai_strerror(rc));
			continue;
		}

		module = module_load(gicht, mod_ptr);
		if (!module) {
			gichtd_log(gicht, LOG_ERR, "Failed to load module %s", mod_ptr ? mod_ptr : "(null)");

			if (mod_ptr) {
				FREEPTR(&mod_ptr);
			}
			freeaddrinfo(result);
			continue;
		}

		for (resptr = result; resptr; resptr = resptr->ai_next) {
			if (0 == _socket(gicht, *lptr, resptr, &fd)) {
				_start(acceptor, module, fd);
				_announce(gicht, *lptr, resptr, mod_ptr);
			}
		}

		freeaddrinfo(result);
	}

	FREEPTR(&mod_ptr);

	return dllist_count(&acceptor->listeners);
}

static void *_thread(void *arg)
{
	thread_t *thread = arg;
	acceptor_t *acceptor = thread->context.data;
	unsigned listening;

	gichtd_log(thread->gicht, LOG_INFO, "Acceptor %lu starting", thread->th_id);
	acceptor->ev = ev_loop_new(0);

	listening = _listen(acceptor, thread->gicht);

	pthread_barrier_wait(&thread->gicht->acceptor.init);

	if (listening > 0) {
		ev_async_init(&acceptor->wakeup, _wakeup);
		ev_async_start(acceptor->ev, &acceptor->wakeup);

		ev_set_userdata(acceptor->ev, thread);
		ev_run(acceptor->ev, 0);
	} else {
		gichtd_log(thread->gicht, LOG_ERR, "Failed to create any listener");
		kill(getpid(), SIGTERM);
	}

	gichtd_log(thread->gicht, LOG_INFO, "Acceptor %lu finished", thread->th_id);
	return NULL;
}

static bool _free_listener_modules(void *item_data, void *empty)
{
	module_io_t *mio = item_data;

	return true;
}

static void _free(void **a)
{
	acceptor_t *acceptor = *(acceptor_t **) a;

	dllist_each(&acceptor->listeners, _free_listener_modules, NULL, false);
	dllist_dtor(&acceptor->listeners);

	if (acceptor->ev) {
		ev_loop_destroy(acceptor->ev);
	}

	FREEPTR(a);
}

thread_t *acceptor_create(gichtd_t *gicht)
{
	thread_t *thread = NULL;
	acceptor_t *acceptor = calloc(1, sizeof(*acceptor));

	if (acceptor) {
		thread = thread_init(gicht, _thread, NULL, acceptor, _free);
	}
	return thread;
}

void acceptor_wakeup(thread_t *thread)
{
	acceptor_t *acceptor = thread->context.data;

	ev_async_send(acceptor->ev, &acceptor->wakeup);
}

/*
 * vim: set noet sw=4 tw=4
 */
