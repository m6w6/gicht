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

struct dlitem {
	context_t item;
	dlitem_t *prev;
	dlitem_t *next;
};

dllist_t *dllist_init(dllist_t *dllist)
{
	INITPTR(dllist);

	return dllist;
}

void dllist_dtor(dllist_t *dllist)
{
	if (dllist) {
		while (dllist_shift(dllist, NULL));
	}
}

void dllist_free(dllist_t **dllist)
{
	dllist_dtor(*dllist);
	FREEPTR(dllist);
}

bool dllist_empty(dllist_t *list)
{
	return !list->first;
}

bool dllist_each(dllist_t *list, dllist_for exe, void *arg, bool reverse)
{
	dlitem_t *ptr;

	if (reverse) {
		for (ptr = list->last; ptr; ptr = ptr->prev) {
			if (!exe(ptr->item.data, arg)) {
				return false;
			}
		}
	} else {
		for (ptr = list->first; ptr; ptr = ptr->next) {
			if (!exe(ptr->item.data, arg)) {
				return false;
			}
		}
	}

	return true;
}

uint64_t dllist_count(dllist_t *list)
{
	uint64_t count = 0;
	dlitem_t *ptr;

	for (ptr = list->first; ptr; ptr = ptr->next) {
		++count;
	}

	return count;
}

int dllist_push(dllist_t *list, context_t *in)
{
	dlitem_t *item = calloc(1, sizeof(*item));

	if (!item) {
		return ENOMEM;
	}

	item->item = *in;
	if (list->last) {
		list->last->next = item;
		item->prev = list->last;
		list->last = item;
	} else {
		list->last = item;
		list->first = item;
	}
	return 0;
}

int dllist_unshift(dllist_t *list, context_t *in)
{
	dlitem_t *item = calloc(1, sizeof(*item));

	if (!item) {
		return ENOMEM;
	}

	item->item = *in;
	if (list->first) {
		list->first->prev = item;
		item->next = list->first;
		list->first = item;
	} else {
		list->first = item;
		list->last = item;
	}
	return 0;
}

bool dllist_find(dllist_t *dllist, context_t *out, bool unlink, dllist_cmp cmp, void *cmp_data)
{
	dlitem_t *ptr;

	for (ptr = dllist->first; ptr; ptr = ptr->next) {
		if (!cmp || !cmp(ptr->item.data, cmp_data)) {
			if (out) {
				*out = ptr->item;
			}

			if (unlink){
				dlitem_t *item = ptr;

				if (item->prev) {
					item->prev->next = item->next;
				}
				if (item->next) {
					item->next->prev = item->prev;
				}

				free(item);
			}

			return true;
		}
	}

	return NULL;
}

void *dllist_next(dllist_t *list, void **ppointer, bool reverse)
{
	dlitem_t *item = *ppointer;

	if (item) {
		item = (reverse ? item->prev : item->next);
	} else {
		item = (reverse ? list->last : list->first);
	}

	*((dlitem_t **) ppointer) = item;

	return item ? item->item.data : NULL;
}

bool dllist_pop(dllist_t *dllist, context_t *out)
{
	dlitem_t *item = dllist->first;

	if (!item) {
		return false;
	}

	if (dllist->last->prev) {
		dllist->last = dllist->last->prev;
	} else {
		dllist->first = NULL;
		dllist->last = NULL;
	}

	if (out) {
		*out = item->item;
	} else {
		context_dtor(&item->item);
	}

	free(item);

	return true;
}

bool dllist_shift(dllist_t *dllist, context_t *out)
{
	dlitem_t *item = dllist->first;

	if (!item) {
		return false;
	}

	if (dllist->first->next) {
		dllist->first = dllist->first->next;
	} else {
		dllist->first = NULL;
		dllist->last = NULL;
	}

	if (out) {
		*out = item->item;
	} else {
		context_dtor(&item->item);
	}

	free(item);

	return true;
}

/*
 * vim: set noet
 */
