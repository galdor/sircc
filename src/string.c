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

#include <ctype.h>
#include <string.h>

#include "sircc.h"

int
sircc_is_breaking_space(int c) {
    return isspace(c) && c != 0xa0; /* NO-BREAK SPACE */
}

char *
sircc_strdup(const char *str) {
    return sircc_strndup(str, strlen(str));
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
sircc_str_convert(char *buf, size_t sz, const char *from, const char *to,
                  size_t *nb_bytes) {
    iconv_t conv;
    char *out, *tmp, *buf_orig;
    size_t inlen, outlen;

    buf_orig = buf;

    conv = iconv_open(to, from);
    if (conv == (iconv_t)-1) {
        sircc_set_error("cannot create iconv descriptor from %s to %s: %s",
                        from, to, strerror(errno));
        return NULL;
    }

    inlen = sz;

    outlen = inlen + 1;
    tmp = sircc_malloc(outlen);
    memset(tmp, 0, outlen);
    out = tmp;

    if (nb_bytes)
        *nb_bytes = 0;

    for (;;) {
        size_t ret;

#ifdef SIRCC_PLATFORM_FREEBSD
        ret = iconv(conv, (const char **)&buf, &inlen, &out, &outlen);
#else
        ret = iconv(conv, &buf, &inlen, &out, &outlen);
#endif
        if (ret == (size_t)-1) {
            if (errno == E2BIG) {
                outlen = (outlen - 1) * 2 + 1;
                tmp = sircc_realloc(tmp, outlen);
                out = tmp;
                continue;
            } else if (errno == EINVAL) {
                /* Truncated sequence */
                break;
            } else {
                sircc_set_error("cannot convert string from %s to %s: %s",
                                from, to, strerror(errno));
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

char *
sircc_str_locale_to_utf8(char *buf, size_t sz, size_t *nb_bytes) {
    return sircc_str_convert(buf, sz, "", "UTF-8", nb_bytes);
}

int
sircc_vasprintf(char **pstr, const char *fmt, va_list ap) {
    struct bf_buffer *buf;

    buf = bf_buffer_new(128);

    bf_buffer_add_vprintf(buf, fmt, ap);
    *pstr = bf_buffer_dup_string(buf);

    bf_buffer_delete(buf);
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

bool
sircc_utf8_is_leading_byte(char c) {
    return ((c & 0x80) == 0x00) /* one byte character */
        || ((c & 0xc0) == 0xc0);
}

bool
sircc_utf8_is_continuation_byte(char c) {
    return (c & 0xc0) == 0x80;
}

size_t
sircc_utf8_sequence_length(char c) {
    if ((c & 0x80) == 0x0) {
        return 1;
    } else if ((c & 0xe0) == 0xc0) {
        return 2;
    } else if ((c & 0xf0) == 0xe0) {
        return 3;
    } else if ((c & 0xf8) == 0xf0) {
        return 4;
    } else {
        return 0;
    }
}

size_t
sircc_utf8_nb_chars(const char *str) {
    size_t nb_chars;

    nb_chars = 0;
    while (*str != '\0') {
        if (sircc_utf8_is_leading_byte(*str))
            nb_chars++;

        str++;
    }

    return nb_chars;
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

