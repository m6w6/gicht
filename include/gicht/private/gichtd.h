#ifndef GICHT_PRIVATE_GICHTD_H_
#define GICHT_PRIVATE_GICHTD_H_

typedef struct gichtd_options gichtd_options_t;

struct gichtd_options {
	/* argv0 */
	char *prog;
	/* argv */
	char **argv;
	/* -o, --options= */
	char *options;
	/* -l, --listen= */
	const char **listen;
	/* -m, --moduledir= */
	const char *moduledir;
	/* -r, --rundir= */
	const char *rundir;

	/* -h, --help */
	unsigned help:1;
	/* -t, --test */
	unsigned test:1;
	/* -k, --kill */
	unsigned kill:1;
	/* -d, --daemon */
	unsigned daemon:1;
	/* -w, --worker= */
	unsigned worker:12;

	/* ---- */
	unsigned restart:1;
};

gichtd_options_t *gichtd_options_init(int argc, char *argv[]);
void gichtd_options_help(gichtd_options_t *options);
void gichtd_options_free(gichtd_options_t **options);

struct gichtd {
	gichtd_options_t *options;
	pid_t pid;
	dllist_t modules;

	struct gicht_running {
		pthread_rwlock_t lock;
		bool flag;
	} running;

	struct gicht_signals {
		ev_signal sighup;
		ev_signal sigint;
		ev_signal sigterm;
	} signals;

	struct gicht_log {
		pthread_mutex_t mutex;
		int level;
	} log;

	struct gicht_acceptor {
		thread_t *thread;
		pthread_barrier_t init;
	} acceptor;

	struct gicht_worker {
		unsigned next;
		thread_t **threads;
		pthread_barrier_t init;
	} worker;
};

#endif
