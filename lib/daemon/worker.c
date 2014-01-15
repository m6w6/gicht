#include "gicht.h"
#include "gicht/private/gichtd.h"

typedef struct worker worker_t;

struct worker {
	ev_async wakeup;
	ev_async work;
	ev_loop *ev;

	struct {
		pthread_rwlock_t lock;
		dllist_t open;
		uint64_t done;
	} clients;
};

static void _free(void **w)
{
	worker_t *worker = *(worker_t **) w;

	pthread_rwlock_destroy(&worker->clients.lock);
	if (worker->ev) {
		ev_loop_destroy(worker->ev);
	}
	FREEPTR(w);
}

struct module_work {
	module_io_t *io;
	module_fd_t *fd;
};

static void _work(ev_loop *ev, ev_async *as, int revents)
{
	thread_t *thread = ev_userdata(ev);
	worker_t *worker = thread->context.data;
	context_t client = {0};
	module_fd_t *mfd;
	module_io_t *mio;
	bool shift;
	int rc;

	if (revents & EV_ASYNC) {
		while (true) {
			rc = pthread_rwlock_wrlock(&worker->clients.lock);

			if (rc) {
				break;
			}

			shift = dllist_shift(&worker->clients.open, &client);
			pthread_rwlock_unlock(&worker->clients.lock);

			if (!shift) {
				break;
			}

			mfd = client.data;
			if (mfd) {
				mio = mfd->module->work(mfd);

				if (mio) {
					chash_add(&mio->contexts, "fd_dtor", &client);
					ev_io_start(ev, &mio->io);
					gichtd_log(thread->gicht, LOG_INFO,
							"Worker %lu work #%lu (fd=%d)", thread->th_id,
							++worker->clients.done, mio->io.fd);
				} else {
					context_dtor(&client);
				}
			}
		}
	}
}

static void _wakeup(ev_loop *ev, ev_async *as, int revents)
{
	thread_t *thread = ev_userdata(ev);
	worker_t *worker = thread->context.data;

	if ((revents & EV_ASYNC) && !gichtd_is_running(thread->gicht)) {
		ev_async_stop(ev, as);
		ev_break(ev, EVBREAK_ONE);
	}
}

static void *_thread(void *arg)
{
	thread_t *thread = arg;
	worker_t *worker = thread->context.data;

	gichtd_log(thread->gicht, LOG_INFO, "Worker %lu starting", thread->th_id);
	worker->ev = ev_loop_new(0);

	ev_async_init(&worker->work, _work);
	ev_async_start(worker->ev, &worker->work);
	ev_async_init(&worker->wakeup, _wakeup);
	ev_async_start(worker->ev, &worker->wakeup);

	ev_set_userdata(worker->ev, thread);
	pthread_barrier_wait(&thread->gicht->worker.init);
	ev_run(worker->ev, 0);

	gichtd_log(thread->gicht, LOG_INFO, "Worker %lu finished", thread->th_id);

	return NULL;
}

thread_t *worker_create(gichtd_t *gicht)
{
	thread_t *thread = NULL;
	worker_t *worker = calloc(1, sizeof(*worker));
	int rc;

	rc = pthread_rwlock_init(&worker->clients.lock, NULL);
	if (!rc) {
		thread = thread_init(gicht, _thread, NULL, worker, _free);
	}
	return thread;
}

int worker_work(thread_t *thread, module_fd_t *client)
{
	worker_t *worker = thread->context.data;
	context_t item;
	int rc;

	client->thread = thread;
	item.data = client;
	item.dtor = (context_data_dtor) module_fd_free;

	rc = pthread_rwlock_wrlock(&worker->clients.lock);
	if (!rc) {
		rc = dllist_push(&worker->clients.open, &item);
	}
	pthread_rwlock_unlock(&worker->clients.lock);

	if (!rc) {
		ev_async_send(worker->ev, &worker->work);
	}
	return rc;
}

void worker_wakeup(thread_t *thread)
{
	worker_t *worker = thread->context.data;

	ev_async_send(worker->ev, &worker->wakeup);
}

/*
 * vim: set noet
 */
