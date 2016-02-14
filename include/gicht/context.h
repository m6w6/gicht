
#ifndef GICHT_CONTEXT_H_
#define GICHT_CONTEXT_H_

typedef struct context context_t;

typedef void (*context_data_dtor)(void **context_data);
void context_data_free(void **data);

struct context {
	void *data;
	context_data_dtor dtor;
};

context_t *context_init(context_t *context, void *data, context_data_dtor dtor);
void context_dtor(context_t *context);
void context_free(context_t **context);

#endif

/*
 * vim: set noet sw=4 ts=4
 */
