#include "gicht.h"

context_t *context_init(context_t *context, void *data, context_data_dtor dtor)
{
	if (!context) {
		context = malloc(sizeof(*context));
	}

	context->data = data;
	context->dtor = dtor;

	return context;
}

void context_dtor(context_t *context)
{
	if (context && context->dtor) {
		context->dtor(&context->data);
	}
}

void context_free(context_t **context)
{
	context_dtor(*context);
	FREEPTR(context);
}

void context_data_free(void **data)
{
	FREEPTR(data);
}

/*
 * vim: set noet sw=4 ts=4
 */
