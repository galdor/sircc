/*
 * Copyright (c) 2013-2014 Nicolas Martyanoff
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

#include <stdio.h>

#include "sircc.h"

#ifndef NDEBUG

static FILE *sircc_debug_file;

void
sircc_debug_initialize(void) {
    sircc_debug_file = fopen(SIRCC_DEBUG_FILE, "w");
    if (!sircc_debug_file)
        die("cannot open debug file %s: %s", SIRCC_DEBUG_FILE, strerror(errno));
}

void
sircc_debug_shutdown(void) {
    fclose(sircc_debug_file);
}

void
sircc_debug(const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vfprintf(sircc_debug_file, fmt, ap);
    va_end(ap);

    fputc('\n', sircc_debug_file);
    fflush(sircc_debug_file);
}

#endif
