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

#ifndef GICHT_CHASH_H
#define GICHT_CHASH_H

#include <gicht/dllist.h>

/*
 * A simple hashtable based on HSEARCH(3) with GNU extensions
 */
typedef struct chash chash_t;

struct chash {
	struct hsearch_data hash;
	dllist_t data;
};

/**
 * Initialize a chash_t structure with \a num_elements.
 * If \a ch is NULL, it will be allocated, else zeroed.
 */
chash_t *chash_init(chash_t *ch, size_t num_elements);

/**
 * Add the contents of context \a val indexed by \a key.
 * Returns true on success.
 */
bool chash_add(chash_t *ch, const char *key, const context_t *val);

/**
 * Find \a key in the hashtable \a ch.
 * Returns the data of the stored context.
 */
void *chash_get(chash_t *ch, const char *key);

/**
 * Destroy the hashtable \a ch.
 */
void chash_dtor(chash_t *ch);

/**
 * Destroy the hashtable \a ch and free the memory allocated for \a ch.
 */
void chash_free(chash_t **ch);

#endif

/*
 * vim: set noet
 */
