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

#ifndef GICHT_DLLIST_H_
#define GICHT_DLLIST_H_

#include <gicht/context.h>

/**
 * Opaque dllist item.
 */
typedef struct dlitem dlitem_t;

/**
 * A simple doubly linked list.
 */
typedef struct dllist {
	dlitem_t *first;
	dlitem_t *last;
} dllist_t;

/**
 * List item comparator. Return 0 if item data equals.
 */
typedef int (*dllist_cmp)(void *item_data, void *cmp_data);

/**
 * List iterator callback. Return false to break.
 */
typedef bool (*dllist_for)(void *item_data, void *exe_data);

/**
 * Initialize the doubly linked list \a list.
 * If \a list is NULL, it will be allocated, else zeroed.
 * Returns NULL if memory cannot be allocated.
 */
dllist_t *dllist_init(dllist_t *list);

/**
 * Check if the \a list is empty.
 */
bool dllist_empty(dllist_t *list);

/**
 * Count the elements int the \a list.
 */
uint64_t dllist_count(dllist_t *list);

/**
 * Destroy, but do not free \a list.
 */
void dllist_dtor(dllist_t *list);

/**
 * Destroy and free \a list.
 */
void dllist_free(dllist_t **list);

/**
 * Push a copy of context \a in at the end of the \a list.
 * Returns 0 on success.
 */
int dllist_push(dllist_t *list, context_t *in);

/**
 * Push a copy if context \a in at the beginning of the \a list.
 * Returns 0 on success.
 */
int dllist_unshift(dllist_t *list, context_t *in);

/**
 * Shift the first item of \a list and copy the item's context into \a out.
 * Returns true if an item was shifted.
 */
bool dllist_shift(dllist_t *list, context_t *out);

/**
 * Pop the last item of \a list and copy the item's context into \a out.
 * Returns true if an item was popped.
 */
bool dllist_pop(dllist_t *dllist, context_t *out);

/**
 * Find an item in \a list by comparing \a cmp_data to the item's context data
 * with \a cmp.
 * Removes the item from the list if \a unlink is TRUE.
 * Returns the matching item context's data.
 */
bool dllist_find(dllist_t *list, context_t *out, bool unlink, dllist_cmp cmp,
		void *cmp_data);

/**
 * Iterate over \a list. If \a reverse is true, iterate from last to first item.
 * \a ppointer is used to remember the current item within the \a list.
 * Returns the data of the next list item, or NULL if the end was reached.
 */
void *dllist_next(dllist_t *list, void **ppointer, bool reverse);

/**
 * Iterate over \a list. If \a reverse is true, iterate from last to first item.
 * Returns true if every item of \a list was visited.
 */
bool dllist_each(dllist_t *dllist, dllist_for exe, void *exe_data, bool reverse);

#endif

/*
 * vim: set noet
 */
