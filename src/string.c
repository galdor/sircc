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

#include <errno.h>
#include <string.h>

#include "sircc.h"

char *
sircc_strdup(const char *str) {
    return strndup(str, strlen(str));
}

char *
sircc_strndup(const char *str, size_t len) {
    char *nstr;

    nstr = sircc_malloc(len + 1);
    memcpy(nstr, str, len);
    nstr[len] = '\0';

    return nstr;
}

char *
sircc_str_to_utf8(char *buf, size_t len, size_t *nb_bytes) {
    iconv_t conv;
    char *out, *tmp, *buf_orig;
    size_t inlen, outlen;

    buf_orig = buf;

    conv = iconv_open("", "UTF-8");
    if (conv == (iconv_t)-1)
        die("cannot create iconv conversion descriptor: %m");

    inlen = len;

    outlen = inlen + 1;
    tmp = sircc_malloc(outlen);
    out = tmp;

    if (nb_bytes)
        *nb_bytes = 0;

    for (;;) {
        if (iconv(conv, &buf, &inlen, &out, &outlen) == (size_t)-1) {
            if (errno == E2BIG) {
                outlen = (outlen - 1) * 2 + 1;
                tmp = sircc_realloc(tmp, outlen);
                out = tmp;
                continue;
            } else if (errno == EINVAL) {
                /* Truncated sequence */
                break;
            } else {
                sircc_set_error("cannot convert string to UTF-8: %m");
                free(tmp);
                return NULL;
            }
        }

        break;
    }

    *out = '\0';
    iconv_close(conv);

    if (nb_bytes)
        *nb_bytes = (size_t)(buf - buf_orig);

    return tmp;
}

int
sircc_vasprintf(char **pstr, const char *fmt, va_list ap) {
    struct sircc_buf buf;

    sircc_buf_init(&buf);

    sircc_buf_add_vprintf(&buf, fmt, ap);
    *pstr = sircc_buf_dup_str(&buf);

    sircc_buf_free(&buf);
    return 0;
}

int
sircc_asprintf(char **pstr, const char *fmt, ...) {
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = sircc_vasprintf(pstr, fmt, ap);
    va_end(ap);

    return ret;
}

#ifndef strlcpy
/*
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
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
size_t
strlcpy(char *dst, const char *src, size_t siz)
{
    char *d = dst;
    const char *s = src;
    size_t n = siz;

    /* Copy as many bytes as will fit */
    if (n != 0) {
        while (--n != 0) {
            if ((*d++ = *s++) == '\0')
                break;
        }
    }

    /* Not enough room in dst, add NUL and traverse rest of src */
    if (n == 0) {
        if (siz != 0)
            *d = '\0';      /* NUL-terminate dst */
        while (*s++)
            ;
    }

    return (size_t)(s - src - 1);    /* count does not include NUL */
}
#endif

