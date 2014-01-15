#include "gicht.h"
#include "gicht/private/gichtd.h"

thread_t *gichtd_worker(gichtd_t *gicht)
{
	thread_t *thread = gicht->worker.threads[gicht->worker.next];
	if (++gicht->worker.next >= gicht->options->worker) {
		gicht->worker.next = 0;
	}
	return thread;
}

bool gichtd_is_running(gichtd_t *gicht)
{
	int rc;
	bool running;

	rc = pthread_rwlock_rdlock(&gicht->running.lock);
	if (rc) {
		return 0;
	}
	running = gicht->running.flag;
	pthread_rwlock_unlock(&gicht->running.lock);
	return running;
}

static const char priorities[][6] = {
		"EMERG",
		"ALERT",
		"CRIT",
		"ERROR",
		"WARN",
		"NOTE",
		"INFO",
		"DEBUG"
};

static void verrlog(int pri, const char *fmt, va_list argv)
{
	char ts[48] = "";
	struct tm tm;
	time_t t = time(NULL);

	strftime(ts, sizeof(ts)-1, "%x %X", localtime_r(&t, &tm));
	fprintf(stderr, "%s gicht[%d] %s: ", ts, getpid(), priorities[MIN(LOG_DEBUG, MAX(LOG_EMERG, pri))]);
	vfprintf(stderr, fmt, argv);
	fprintf(stderr, "\n");
}

void gichtd_log(gichtd_t *gicht, int pri, const char *fmt, ...)
{
	int local_errno = errno;
	va_list argv;

	if (!gicht || (gicht->log.level <= pri)) {
		va_start(argv, fmt);

		if (!gicht || 0 == pthread_mutex_lock(&gicht->log.mutex)) {
			if (!gicht || !gicht->options->daemon) {
				verrlog(pri, fmt, argv);
			} else {
				vsyslog(pri, fmt, argv);
			}

			if (gicht) {
				pthread_mutex_unlock(&gicht->log.mutex);
			}
		}
		va_end(argv);
	}

	errno = local_errno;
}

/*
 * vim: set noet ts=4 sw=4
 */
