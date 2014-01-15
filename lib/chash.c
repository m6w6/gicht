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

#include "gicht.h"

typedef struct chash_entry chash_entry_t;

struct chash_entry {
	context_t self;
	context_t val;
	char *key;
};

/*
 * TODO:
 * - resize
 * - delete
 */

chash_t *chash_init(chash_t *ch, size_t num_elements)
{
	bool alloc = !!ch;

	INITPTR(ch);

	if (ch) {
		if (!hcreate_r(num_elements, &ch->hash)) {
			if (alloc) {
				FREEPTR(&ch);
			}
		}
	}

	return ch;
}

static void _dtor(void **e)
{
	chash_entry_t *entry = *(chash_entry_t **) e;

	context_dtor(&entry->val);
	FREEPTR(e);
}

static int _find(void *entry_data, void *cmp_data)
{
	return entry_data != cmp_data;
}

bool chash_add(chash_t *ch, const char *key, const context_t *val)
{
	ENTRY E, *R = NULL;
	chash_entry_t *entry = calloc(1, sizeof(*entry) + strlen(key) + 1);

	entry->self.data = entry;
	entry->self.dtor = _dtor;

	entry->val = *val;
	entry->key = (char *) entry + sizeof(*entry);
	strcpy(entry->key, key);

	if (0 != dllist_push(&ch->data, &entry->self)) {
		free(entry);
		return false;
	}

	E.data = &entry->val;
	E.key = entry->key;

	if (!hsearch_r(E, ENTER, &R, &ch->hash)) {
		dllist_find(&ch->data, NULL, true, _find, entry);
		free(entry);
		return false;
	}

	return true;
}

void *chash_get(chash_t *ch, const char *key)
{
	ENTRY E, *R = NULL;

	E.key = strdup(key);

	if (!hsearch_r(E, FIND, &R, &ch->hash)) {
		free(E.key);
		return NULL;
	}
	free(E.key);

	return ((context_t *) R->data)->data;
}

void chash_dtor(chash_t *ch)
{
	if (ch) {
		dllist_dtor(&ch->data);
		hdestroy_r(&ch->hash);
	}
}

void chash_free(chash_t **ch)
{
	chash_dtor(*ch);
	FREEPTR(ch);
}

/*
 * vim: set noet
 */
