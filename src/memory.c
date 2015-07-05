/*
 * Copyright (c) 2013-2015 Nicolas Martyanoff
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "sircc.h"

const struct c_memory_allocator sircc_memory_allocator = {
    .malloc = sircc_malloc,
    .free = sircc_free,
    .calloc = sircc_calloc,
    .realloc = sircc_realloc,
};

void *
sircc_malloc(size_t sz) {
    void *ptr;

    ptr = malloc(sz);
    if (!ptr)
        die("cannot allocate %zu bytes: %s", sz, strerror(errno));

    return ptr;
}

void
sircc_free(void *ptr) {
    free(ptr);
}


void *
sircc_calloc(size_t nb, size_t sz) {
    void *ptr;

    ptr = calloc(nb, sz);
    if (!ptr)
        die("cannot allocate %zux%zu bytes: %s", nb, sz, strerror(errno));

    return ptr;
}

void *
sircc_realloc(void *ptr, size_t sz) {
    void *nptr;

    nptr = realloc(ptr, sz);
    if (!nptr)
        die("cannot reallocate %zu bytes: %s", sz, strerror(errno));

    return nptr;
}
