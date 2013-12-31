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

#include <openssl/err.h>

#include "sircc.h"

static __thread char sircc_ssl_error_buf[SIRCC_ERROR_BUFSZ];

const char *
sircc_ssl_get_error(void) {
    char *ptr;
    size_t len;

    ptr = sircc_ssl_error_buf;
    len = SIRCC_ERROR_BUFSZ;

    for (;;) {
        unsigned long errcode;
        const char *errstr;
        size_t errlen;

        errcode = ERR_get_error();
        if (errcode == 0)
            break;

        errstr = ERR_error_string(errcode, NULL);
        strlcpy(ptr, errstr, len);

        errlen = strlen(errstr);
        if (errlen >= len)
            break;

        ptr += errlen;
        len -= errlen;
    }

    if (ptr == sircc_ssl_error_buf)
        strlcpy(ptr, "empty ssl error queue", len);

    return sircc_ssl_error_buf;
}
