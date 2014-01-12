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
    bool empty_queue;

    ptr = sircc_ssl_error_buf;
    len = SIRCC_ERROR_BUFSZ;

    empty_queue = true;

    for (;;) {
        unsigned long errcode;
        const char *errstr;
        size_t errlen;

        if (ptr > sircc_ssl_error_buf) {
            *ptr = ' ';
            ptr++;
            len--;
        }

        errcode = ERR_get_error();
        if (errcode == 0)
            break;

        empty_queue = false;

        errstr = ERR_error_string(errcode, NULL);
        strlcpy(ptr, errstr, len);

        errlen = strlen(errstr);
        if (errlen >= len)
            break;

        ptr += errlen;
        len -= errlen;
    }

    if (empty_queue)
        strlcpy(ptr, "empty ssl error queue", len);

    return sircc_ssl_error_buf;
}

int
sircc_x509_store_add_certificate(X509_STORE *store, const char *path) {
    X509_LOOKUP *lookup;

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (!lookup) {
        sircc_set_error("cannot create ssl store lookup: %s",
                        sircc_ssl_get_error());
        return -1;
    }

    if (X509_LOOKUP_load_file(lookup, path, X509_FILETYPE_PEM) == 0) {
        sircc_set_error("cannot load ssl certificate from %s: %s",
                        path, sircc_ssl_get_error());
        return -1;
    }

    return 0;
}
