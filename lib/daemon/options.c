
#include "gicht.h"
#include "gicht/private/gichtd.h"

#define long_options_count (int)(sizeof(long_options)/sizeof(struct option))-1
static struct option long_options[] = {
		{"help",      no_argument,       0, 'h'},
		{"test",      no_argument,       0, 't'},
		{"kill",      no_argument,       0, 'k'},
		{"daemon",    no_argument,       0, 'd'},
		{"worker",    required_argument, 0, 'w'},
		{"listen",    required_argument, 0, 'l'},
		{"moduledir", required_argument, 0, 'm'},
		{"rundir",    required_argument, 0, 'r'},
		{"options",   required_argument, 0, 'o'},
		{0,           0,                 0, 0}
};

static const char *desc_options[] = {
		"Display this help",
		"Test for a running daemon",
		"Kill a running daemon",
		"Run as a daemnon",
		"Number of worker threads [_SC_NPROCESSORS_ONLN]",
		"Listen specification (e.g. echo+ssl@localhost:4433)",
		"Directory where loadable modules are located",
		"Directory where to store run state (PID file, etc.)",
		"Module options"
};

static const char space[] = "                                        "
		"                                        ";

static char short_options_tmp[long_options_count * 3];

static const char *default_listen[] = {
		"echo@localhost:9999"
};

static char default_moduledir[FILENAME_MAX];

static const char *short_options(void) {
	if (!short_options_tmp[0]) {
		int i, j;
		char *ptr = short_options_tmp;

		for (i = 0; i < long_options_count; ++i) {
			if (!long_options[i].flag) {
				*ptr++ = long_options[i].val;
			}
			for (j = 0; j < long_options[i].has_arg; ++j) {
				*ptr++ = ':';
			}
		}
	}
	return short_options_tmp;
}

gichtd_options_t *gichtd_options_init(int argc, char *argv[])
{
	int optindex, optchar, opttmp;
	char *prog = strdup(argv[0]);
	gichtd_options_t *options = calloc(1, sizeof(*options));

	options->prog = strdup(basename(prog));
	free(prog);
	options->argv = argv;

	options->worker = sysconf(_SC_NPROCESSORS_ONLN);
	options->listen = default_listen;
	options->moduledir = getcwd(default_moduledir, sizeof(default_moduledir)-1);
	options->rundir = "/var/run";

	while (-1 != (optchar = getopt_long(argc, argv, short_options(), long_options, &optindex))) {
		switch (optchar) {
		case '?':
		case 'h':
			options->help = 1;
			break;

		case 't':
			options->test = 1;
			break;

		case 'k':
			options->kill = 1;
			break;

		case 'd':
			options->daemon = 1;
			break;

		case 'w':
			opttmp = atoi(optarg);
			options->worker = MAX(1, MIN(opttmp, 4096));
			break;

		case 'l':
			if (options->listen == default_listen) {
				opttmp = 1;
				options->listen = calloc(2, sizeof(char *));
			} else {
				for (opttmp = 0; options->listen[opttmp]; ++opttmp);
				options->listen = realloc(options->listen, (opttmp + 1) * sizeof(char));
				options->listen[opttmp] = NULL;
			}
			options->listen[opttmp-1] = optarg;
			break;

		case 'm':
			options->moduledir = optarg;
			break;

		case 'r':
			options->rundir = optarg;
			break;

		case 'o':
			if (options->options) {
				options->options = realloc(options->options,
					strlen(optarg) + strlen(options->options) + 1 + 1);
				sprintf(options->options + strlen(options->options), ",%s",
						optarg);
			} else {
				options->options = strdup(optarg);
			}
			break;
		}
	}

	return options;
}


void gichtd_options_help(gichtd_options_t *options) {
	int i, p;
	size_t m = 0;
#define w(m) (m * 2 + sizeof("  -X, --"/*name*/"=<"/*name*/"> "))
#define s(p) (&space[sizeof(space) - w(m) + p])

	printf("GICHT v%s\n\n", GICHT_VERSION_STR);

	printf("Usage: %s [-", options->prog);
	for (i = 0; i < long_options_count; ++i) {
		if (!long_options[i].has_arg) {
			printf("%c", long_options[i].val);
		}
	}
	printf("] [<options>]\n\n");


	for (i = 0; i < long_options_count; ++i) {
		size_t l = strlen(long_options[i].name);

		if (l > m) {
			m = l;
		}

		if (!long_options[i].has_arg) {
			printf("  -%c, --%s\t%s\n", long_options[i].val,
					long_options[i].name, desc_options[i]);
		}
	}
	printf("\n");

	printf("Options:\n");
	for (i = 0; i < long_options_count; ++i) {
		switch (long_options[i].has_arg) {
		case required_argument:
			p = printf("  -%1$c, --%2$s=<%2$s>", long_options[i].val,
					long_options[i].name);
			printf("%s%s\n", s(p), desc_options[i]);
			break;

		case optional_argument:
			p = printf("  -%1$c, --%2$s=[%2$s]", long_options[i].val,
					long_options[i].name);
			printf("%s%s\n", s(p), desc_options[i]);
			break;
		}
	}
	printf("\n");

	printf("Examples:\n");
	printf("  %s -d \\\n", options->prog);
	printf("    -m /usr/local/lib/gicht \\\n");
	printf("    -r /run/gicht \\\n");
	printf("    -l echo+ssl@localhost:4433 \\\n");
	printf("    -o ssl_cert=/etc/gicht/ssl.crt \\\n");
	printf("    -o ssl_key_rsa=/etc/gicht/ssl.key\n");
	printf("\n");
}

void gichtd_options_free(gichtd_options_t **options) {
	if (*options) {
		free((*options)->prog);
		if ((*options)->listen != default_listen) {
			free((*options)->listen);
		}
		if ((*options)->options) {
			free((*options)->options);
		}
		free(*options);
		*options = NULL;
	}
}
