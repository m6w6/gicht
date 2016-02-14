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

#ifndef GICHT_H_
#define GICHT_H_

#undef EV_COMPAT3
#define EV_COMPAT3 0

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
/* see https://www.gnu.org/software/autoconf/manual/autoconf-2.69/html_node/Header-Portability.html */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif
#ifdef HAVE_GETOPT_H
#include <getopt.h> /* GNU long options */
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif defined( HAVE_INTTYPES_H )
#include <inttypes.h>
#endif
#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#else
#define bool uint_fast8_t
#define true 1
#define false 0
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif
#ifdef HAVE_SEARCH_H
#include <search.h>
#endif

#ifdef HAVE_EV_H
#include <ev.h>
#endif

#define INITPTR(p) do {\
	if (p) {\
		memset((p), 0, sizeof(*(p)));\
	} else {\
		(p) = calloc(1, sizeof(*(p)));\
	}\
} while(0)

#define FREEPTR(pp) do {\
	if (*(pp)) {\
		free(*(pp));\
		*(pp) = NULL;\
	}\
} while(0)

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

typedef struct gichtd gichtd_t;
typedef struct thread thread_t;

#include <gicht_version.h>
#include <gicht/dllist.h>
#include <gicht/context.h>
#include <gicht/chash.h>
#include <gicht/module.h>

typedef void *(*thread_run)(void *thread_arg);

struct thread {
	pthread_t th_id;
	gichtd_t *gicht;
	context_t context;
	chash_t storage;
};

void gichtd_log(gichtd_t *gicht, int pri, const char *fmt, ...);
bool gichtd_is_running(gichtd_t *gicht);
thread_t *gichtd_worker(gichtd_t *gicht);

thread_t *thread_init(gichtd_t *gicht, thread_run run, const pthread_attr_t *attr, void *context_data, context_data_dtor context_dtor);
int thread_join(thread_t *thread);
void thread_free(thread_t **thread);

thread_t *acceptor_create(gichtd_t *gicht);
void acceptor_wakeup(thread_t *thread);

thread_t *worker_create(gichtd_t *gicht);
int worker_work(thread_t *thread, module_fd_t *client);
void worker_wakeup(thread_t *thread);

#endif /* GICHT_H_ */
