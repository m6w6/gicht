#include "gicht.h"
#include "gicht/private/gichtd.h"

static gichtd_t *gichtd_init(gichtd_options_t *options)
{
	gichtd_t *gicht;

	if (options->daemon) {
		openlog("gicht", LOG_PID | LOG_CONS, LOG_DAEMON);
	}

    gicht = calloc(1, sizeof(*gicht));
    gicht->options = options;

    pthread_mutex_init(&gicht->log.mutex, NULL);
    pthread_rwlock_init(&gicht->running.lock, NULL);
    pthread_barrier_init(&gicht->acceptor.init, NULL, 1 + 1);
    pthread_barrier_init(&gicht->worker.init, NULL, options->worker + 1);

    return gicht;
}

static pid_t gichtd_pid_exists(gichtd_t *gicht, bool warn_fopen)
{
	FILE *fh;
	char fn[FILENAME_MAX];
	unsigned long pid;

	snprintf(fn, sizeof(fn) - 1, "%s/gicht.pid", gicht->options->rundir);

	/* TODO file locking */

	fh = fopen(fn, "r");
	if (!fh) {
		if (warn_fopen) {
			gichtd_log(gicht, LOG_WARNING, "Failed to open file: '%s'", fn);
		}
		return (pid_t) -1;
	}

	if (1 != fscanf(fh, "%lu", &pid)) {
		int local_errno = errno;

		fclose(fh);
		errno = local_errno;

		return (pid_t) -1;
	}

	fclose(fh);

	return (pid_t) pid;
}

static int gichtd_pid_kill(gichtd_t *gicht, int s, time_t timeout)
{
	pid_t pid = gichtd_pid_exists(gicht, s);

	if (pid == (pid_t) -1) {
		return pid;
	}

	/* TODO timeout */

	return kill(pid, s);
}

static int gichtd_pid_remove(gichtd_t *gicht)
{
	char fn[FILENAME_MAX];

	snprintf(fn, sizeof(fn) - 1, "%s/gicht.pid", gicht->options->rundir);
	gichtd_log(gicht, LOG_INFO, "Removing pid file: %s", fn);

	return unlink(fn);
}

static int gichtd_pid_create(gichtd_t *gicht)
{
	int fd;
	FILE *fh;
	char fn[FILENAME_MAX];

	snprintf(fn, sizeof(fn) - 1, "%s/gicht.pid", gicht->options->rundir);
	gichtd_log(gicht, LOG_INFO, "Creating pid file: %s", fn);

	fd = open(fn, O_WRONLY | O_CLOEXEC | O_CREAT | O_EXCL, 0644);
	if (fd < 0) {
		return fd;
	}

	/* TODO file locking */

	fh = fdopen(fd, "w");
	if (!fh) {
		int local_errno = errno;

		close(fd);
		unlink(fn);
		errno = local_errno;

		return -1;
	}

	if (0 > fprintf(fh, "%lu\n", (unsigned long) (gicht->pid = getpid()))) {
		int local_errno = errno;

		fclose(fh);
		unlink(fn);
		errno = local_errno;

		return -1;
	}

	fclose(fh);

	return 0;
}

static bool gichtd_oneshot(gichtd_t *gicht, int *rc)
{
	*rc = 0;

	if (gicht->options->kill) {
		if ((*rc = gichtd_pid_kill(gicht, SIGTERM, 5)) < 0) {
			gichtd_log(gicht, LOG_WARNING, "Failed to kill daemon: %s",
					strerror(errno));
		}
		if (*rc && errno != ENOENT && (*rc = gichtd_pid_remove(gicht)) < 0) {
			gichtd_log(gicht, LOG_WARNING, "Failed to remove pid file: %s",
					strerror(errno));
		}
		return true;
	}

	if (gicht->options->test) {
		if ((*rc = gichtd_pid_kill(gicht, 0, 0)) < 0) {
			if (errno == EPERM) {
				*rc = 0;
			} else if (errno != ENOENT){
				gichtd_log(gicht, LOG_WARNING, "Lone pid file (%s)",
						strerror(errno));
				gichtd_pid_remove(gicht);
			}
		}
		return true;
	}

	if (gicht->options->help) {
		gichtd_options_help(gicht->options);
		return true;
	}

	return false;
}

static int gichtd_set_running(gichtd_t *gicht, bool running)
{
	int rc;

	rc = pthread_rwlock_wrlock(&gicht->running.lock);
	if (rc) {
		return rc;
	}
	gicht->running.flag = running;
	return pthread_rwlock_unlock(&gicht->running.lock);
}

static void gichtd_onsignal(ev_loop *ev, ev_signal *sig, int revents)
{
	if (sig->signum == SIGHUP) {
		gichtd_t *gicht = ev_userdata(ev);
		gicht->options->restart = 1;
	}

	ev_break(ev, EVBREAK_ALL);
}

static int gichtd_loop(gichtd_t *gicht)
{
	struct sigaction sigpipe;
	ev_loop *ev;
	int i;

	if (gicht->options->daemon) {
		if (0 != daemon(1, 0)) {
			gichtd_log(gicht, LOG_ERR, "Failed to daemonize: %s", strerror(errno));
			return -1;
		}

		if (0 > gichtd_pid_create(gicht)) {
			gichtd_log(gicht, LOG_ERR, "Failed to create PID file: %s",
					strerror(errno));
			return -1;
		}
	}

	gicht->worker.threads = calloc(gicht->options->worker + 1,
			sizeof(*gicht->worker.threads));
	if (!gicht->worker.threads) {
		return ENOMEM;
	}
	for (i = 0; i < gicht->options->worker; ++i) {
		gicht->worker.threads[i] = worker_create(gicht);
		if (!gicht->worker.threads[i]) {
			return ENOMEM;
		}
	}
	pthread_barrier_wait(&gicht->worker.init);
	gichtd_log(gicht, LOG_INFO, "Initialized %u worker threads",
			gicht->options->worker);

	gicht->acceptor.thread = acceptor_create(gicht);
	if (!gicht->acceptor.thread) {
		return ENOMEM;
	}
	pthread_barrier_wait(&gicht->acceptor.init);

	sigpipe.sa_handler = SIG_IGN;
	sigpipe.sa_flags = SA_RESTART;
	sigemptyset(&sigpipe.sa_mask);
	sigaction(SIGPIPE, &sigpipe, NULL);

	ev = ev_default_loop(0);
	ev_set_userdata(ev, gicht);

	ev_signal_init(&gicht->signals.sighup, gichtd_onsignal, SIGHUP);
	ev_signal_init(&gicht->signals.sigint, gichtd_onsignal, SIGINT);
	ev_signal_init(&gicht->signals.sigterm, gichtd_onsignal, SIGTERM);
	ev_signal_start(ev, &gicht->signals.sighup);
	ev_signal_start(ev, &gicht->signals.sigint);
	ev_signal_start(ev, &gicht->signals.sigterm);

	gichtd_set_running(gicht, 1);
	gichtd_log(gicht, LOG_INFO, "Daemon started");
	ev_run(ev, 0);
	gichtd_log(gicht, LOG_INFO, "Daemon stopping");
	gichtd_set_running(gicht, 0);

	if (gicht->acceptor.thread) {
		acceptor_wakeup(gicht->acceptor.thread);
		thread_join(gicht->acceptor.thread);
	}
	for (i = 0; i < gicht->options->worker; ++i) {
		if (gicht->worker.threads[i]) {
			worker_wakeup(gicht->worker.threads[i]);
			thread_join(gicht->worker.threads[i]);
		}
	}

	if (gicht->options->daemon) {
		if (gicht->pid && gichtd_pid_remove(gicht) < 0) {
			gichtd_log(gicht, LOG_WARNING, "Failed to remove pid file: %s",
					strerror(errno));
		}

		closelog();
	}

	return gicht->options->restart;
}

static void gichtd_free(gichtd_t **gicht)
{
	if (*gicht) {
		int i;

		if ((*gicht)->acceptor.thread) {
			thread_free(&(*gicht)->acceptor.thread);
		}
		if ((*gicht)->worker.threads) {
			for (i = 0; i < (*gicht)->options->worker; ++i) {
				if ((*gicht)->worker.threads[i]) {
					thread_free(&(*gicht)->worker.threads[i]);
				}
			}
			free((*gicht)->worker.threads);
		}

		dllist_dtor(&(*gicht)->modules);

		pthread_barrier_destroy(&(*gicht)->worker.init);
		pthread_rwlock_destroy(&(*gicht)->running.lock);
		gichtd_options_free(&(*gicht)->options);
		free(*gicht);
		*gicht = NULL;
	}
}

int main(int argc, char *argv[]) {
	int rc = 0;
	ev_loop *ev;
	gichtd_t *gicht;
	gichtd_options_t *options;

	ev = ev_default_loop(0);
	if (!ev) {
		gichtd_log(NULL, LOG_ERR, "Failed to initialize event module: %s", strerror(errno));
		return 1;
	}

	options = gichtd_options_init(argc, argv);
	if (!options) {
		gichtd_log(NULL, LOG_ERR, "Failed to initialize commandline options: %s", strerror(errno));
		return 2;
	}

	gicht = gichtd_init(options);
	if (!gicht) {
		gichtd_log(NULL, LOG_ERR, "Failed to initialize gicht daemon: %s", strerror(errno));
		return 3;
	}

	if (!gichtd_oneshot(gicht, &rc)) {
		while (1 == (rc = gichtd_loop(gicht))) {
			execvp(argv[0], argv);
		}
	}

	gichtd_free(&gicht);

	ev_loop_destroy(ev);

	return rc;
}

/*
 * vim: set noet ts=4 sw=4
 */
