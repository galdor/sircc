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

#include <assert.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>

#include "sircc.h"

size_t
bf_buffer_utf8_nb_chars(const struct bf_buffer *buf) {
    size_t nb_chars;
    char *ptr;
    size_t len;

    nb_chars = 0;

    ptr = bf_buffer_data(buf);
    len = bf_buffer_length(buf);

    for (size_t i = 0; i < len; i++) {
        if (sircc_utf8_is_leading_byte(*ptr))
            nb_chars++;

        ptr++;
    }

    return nb_chars;
}

char *
bf_buffer_utf8_last_n_chars(const struct bf_buffer *buf, size_t n,
                            size_t *nb_bytes) {
    char *data, *end, *ptr;
    size_t nb_chars;
    size_t len;

    data = bf_buffer_data(buf);
    if (!data)
        return NULL;
    len = bf_buffer_length(buf);

    if (n >= len) {
        *nb_bytes = len;
        return data;
    }

    nb_chars = 0;

    end = data + len;

    ptr = end;
    do {
        ptr--;

        if (sircc_utf8_is_leading_byte(*ptr))
            nb_chars++;
    } while (nb_chars < n);

    *nb_bytes = (size_t)(end - ptr);
    return ptr;
}
