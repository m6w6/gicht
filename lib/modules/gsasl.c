
#if HAVE_LIBGSASL

#include <gicht.h>


#include <gsasl.h>
#include <sasl/sasl.h>

typedef struct sasl sasl_t;

struct sasl {
	Gsasl *gsasl;
};

/**
 * Gsasl_callback_function:
 * @ctx: libgsasl handle.
 * @sctx: session handle, may be NULL.
 * @prop: enumerated value of Gsasl_property type.
 *
 * It is called by the SASL library when it need some information
 * from the application.  Depending on the value of @prop, it should
 * either set some property (e.g., username or password) using
 * gsasl_property_set(), or it should extract some properties (e.g.,
 * authentication and authorization identities) using
 * gsasl_property_fast() and use them to make a policy decision,
 * perhaps returning GSASL_AUTHENTICATION_ERROR or GSASL_OK
 * depending on whether the policy permitted the operation.
 *
 * Return value: Any valid return code, the interpretation of which
 *   depend on the @prop value.
 */
static int sasl_callback(Gsasl *ctx, Gsasl_session *sctx, Gsasl_property prop)
{

}

static void sasl_dtor(module_t *module)
{
	sasl_t *sasl = module->context.data;

	if (sasl->gsasl) {
		gsasl_done(sasl->gsasl);
		sasl->gsasl = NULL;
	}
	free(sasl);
}

static bool sasl_init(module_t *module, chash_t *config, gicht_t *gicht)
{
	sasl_t *sasl = calloc(1, sizeof(*sasl));
	int rc;

	module->context.data = sasl;

	rc = gsasl_init(&sasl->gsasl);
	if (GSASL_OK != rc) {
		sasl_dtor(module);
		return false;
	}

	gsasl_callback_set(sasl->gsasl, sasl_callback);

	return true;
}

static module_t gsasl_module = {
		0,
		GICHT_VERSION(0,0,1),
		"gsasl",
		{NULL, NULL},
		NULL, /* options */
		sasl_init,
		sasl_dtor,
		NULL,
		NULL,
		NULL,
		NULL
};

module_t *gicht_get_module(void)
{
	return &gsasl_module;
}

#endif

/*
 * vim: set noet ts=4 sw=4
 */
