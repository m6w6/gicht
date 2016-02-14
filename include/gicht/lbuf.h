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

#ifndef GICHT_LBUF_H_
#define GICHT_LBUF_H_

/**
 * A simple line buffer.
 */
typedef struct lbuf {
	char *buf;
	size_t len;
	size_t mem;
} lbuf_t;

/**
 * Intialize the line buffer \a lbuf.
 * If \a lbuf is NULL, it will be allocated, else zeroed.
 * Returns NULL if memory cannot be allocated.
 */
lbuf_t *lbuf_init(lbuf_t *lbuf);

/**
 * Destroy, but do not free the line buffer \a lbuf.
 */
void lbuf_dtor(lbuf_t *lbuf);

/**
 * Destroy and free \æ lbuf.
 */
void lbuf_free(lbuf_t **lbuf);

/**
 * Add the string \a buf of length \a len to the line buffer \a lbuf.
 * Returns 0 on success, or ENOMEM if memory cannot be allocated.
 * In case a line is available to lbuf_get, \a lf will be set to true.
 */
int lbuf_add(lbuf_t *lbuf, const char *buf, size_t len, bool *lf);

/**
 * Cut \a len bytes from the beginning of the line buffer \a lbuf.
 */
void lbuf_cut(lbuf_t *lbuf, size_t len);

/**
 * Get a line from the buffer \a lbuf.
 * Returns a pointer to the beginning of the line and sets \a len to the length
 * of the line including EOL.
 */
char *lbuf_get(lbuf_t *lbuf, size_t *len);

#endif

/*
 * vim: set noet
 */
