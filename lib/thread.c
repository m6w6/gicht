#include "gicht.h"

thread_t *thread_init(gichtd_t *gicht, thread_run run, const pthread_attr_t *attr, void *ctx_data, context_data_dtor ctx_dtor)
{
	int rc;
	thread_t *thread;

	thread = calloc(1, sizeof(*thread));
	thread->gicht = gicht;
	thread->context.data = ctx_data;
	thread->context.dtor = ctx_dtor;

	chash_init(&thread->storage, 64);

	rc = pthread_create(&thread->th_id, attr, run, thread);
	if (rc) {
		gichtd_log(gicht, LOG_EMERG, "Failed to create thread: %s", strerror(rc));
		thread_free(&thread);
	}

	return thread;
}

int thread_join(thread_t *thread)
{
	int rc;
	void *rv = NULL;

	rc = pthread_join(thread->th_id, &rv);
	if (rc) {
		gichtd_log(thread->gicht, LOG_CRIT, "Failed to join thread: %s", strerror(rc));
	}
	context_dtor(&thread->context);
	return rc;
}

void thread_free(thread_t **thread)
{
	if (*thread) {
		free(*thread);
		*thread = NULL;
	}
}
