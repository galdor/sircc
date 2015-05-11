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

#include "sircc.h"

int
sircc_is_breaking_space(int c) {
    return isspace(c) && c != 0xa0; /* NO-BREAK SPACE */
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
                sircc_free(tmp);
                iconv_close(conv);
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
