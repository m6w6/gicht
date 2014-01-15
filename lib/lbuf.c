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
#include "gicht/lbuf.h"

lbuf_t *lbuf_init(lbuf_t *lbuf)
{
	INITPTR(lbuf);

	return lbuf;
}

void lbuf_dtor(lbuf_t *lbuf)
{
	if (lbuf) {
		if (lbuf->buf) {
			free(lbuf->buf);
			lbuf->buf = NULL;
		}
	}
}

void lbuf_free(lbuf_t **lbuf)
{
	lbuf_dtor(*lbuf);
	FREEPTR(lbuf);
}

int lbuf_add(lbuf_t *lbuf, const char *buf, size_t len, bool *lf)
{
	char *ptr;
	size_t off;

	if (lbuf->mem < lbuf->len + len) {
		ptr = realloc(lbuf->buf, lbuf->len + len);
		if (!ptr) {
			return ENOMEM;
		}
		lbuf->mem = lbuf->len + len;
		lbuf->buf = ptr;
	}

	for (off = 0; off < len; ++off) {
		if ('\n' == (lbuf->buf[lbuf->len + off] = buf[off])) {
			*lf = true;
		}
	}
	lbuf->len += len;

	return 0;
}

void lbuf_cut(lbuf_t *lbuf, size_t len)
{
	memmove(lbuf->buf, lbuf->buf + len, lbuf->len - len);
	lbuf->len -= len;
}

char *lbuf_get(lbuf_t *lbuf, size_t *len)
{
	char *ptr;

	if ((ptr = memchr(lbuf->buf, '\n', lbuf->len))) {
		*len = ptr - lbuf->buf + 1;
		return lbuf->buf;
	}
	return NULL;
}


/*
 * vim: set noet sw=4 ts=4
 */
