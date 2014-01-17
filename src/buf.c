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

/*
 *                       sz
 *   <----------------------------------------->
 *
 *    skip             len
 *   <----> <------------------------>
 *
 *  +------------------------------------------+
 *  |      |         content          |        |
 *  +------------------------------------------+
 */

void
sircc_buf_init(struct sircc_buf *buf) {
    memset(buf, 0, sizeof(struct sircc_buf));
}

void
sircc_buf_free(struct sircc_buf *buf) {
    if (!buf->data)
        return;

    sircc_free(buf->data);
    buf->data = NULL;
}

struct sircc_buf *
sircc_buf_new(void) {
    struct sircc_buf *buf;

    buf = sircc_malloc(sizeof(struct sircc_buf));

    sircc_buf_init(buf);
    return buf;
}

void
sircc_buf_delete(struct sircc_buf *buf) {
    if (!buf)
        return;

    sircc_buf_free(buf);
    sircc_free(buf);
}

char *
sircc_buf_data(const struct sircc_buf *buf) {
    return buf->data + buf->skip;
}

size_t
sircc_buf_length(const struct sircc_buf *buf) {
    return buf->len;
}

size_t
sircc_buf_free_space(const struct sircc_buf *buf) {
    return buf->sz - buf->len - buf->skip;
}

void
sircc_buf_repack(struct sircc_buf *buf) {
    if (buf->skip == 0)
        return;

    memmove(buf->data, buf->data + buf->skip, buf->len);
    buf->skip = 0;
}

void
sircc_buf_resize(struct sircc_buf *buf, size_t sz) {
    if (buf->data) {
        buf->data = sircc_realloc(buf->data, sz);
    } else {
        buf->data = sircc_malloc(sz);
    }

    buf->sz = sz;
}

void
sircc_buf_grow(struct sircc_buf *buf, size_t n) {
    sircc_buf_resize(buf, buf->sz + n);
}

void
sircc_buf_ensure_free_space(struct sircc_buf *buf, size_t n) {
    size_t free_space;

    free_space = sircc_buf_free_space(buf);
    if (free_space < n)
        sircc_buf_grow(buf, n - free_space);
}

void
sircc_buf_clear(struct sircc_buf *buf) {
    buf->skip = 0;
    buf->len = 0;
}

void
sircc_buf_insert(struct sircc_buf *buf, size_t offset,
                 const char *data, size_t sz) {
    char *ptr;

    assert(offset <= buf->len);

    if (!buf->data) {
        buf->data = sircc_malloc(sz);
        buf->sz = sz;
    } else if (sircc_buf_free_space(buf) < sz) {
        sircc_buf_repack(buf);

        if (sircc_buf_free_space(buf) < sz) {
            size_t newsz;

            if (sz > buf->sz) {
                newsz = buf->sz + sz;
            } else {
                newsz = buf->sz * 2;
            }

            sircc_buf_resize(buf, newsz);
        }
    }

    ptr = buf->data + buf->skip + offset;

    if (offset < buf->len)
        memmove(ptr + sz, ptr, buf->len - offset);
    memcpy(ptr, data, sz);

    buf->len += sz;
}

void
sircc_buf_add(struct sircc_buf *buf, const char *data, size_t sz) {
    sircc_buf_insert(buf, buf->len, data, sz);
}

void
sircc_buf_add_buf(struct sircc_buf *buf, const struct sircc_buf *src) {
    sircc_buf_add(buf, src->data + src->skip, src->len);
}

int
sircc_buf_add_vprintf(struct sircc_buf *buf, const char *fmt, va_list ap) {
    size_t fmt_len, free_space;
    char *ptr;

    fmt_len = strlen(fmt);
    if (fmt_len == 0) {
        /* If there is no free space in the buffer after its content, and if
         * the format string is empty, the pointer to this free space will be
         * invalid. We may as well return right now. */
        sircc_set_error("empty format string");
        return -1;
    }

    /* We need to make space for \0 because vsnprintf() needs it, even
     * though we will ignore it. */
    sircc_buf_ensure_free_space(buf, fmt_len + 1);

    for (;;) {
        int ret;
        va_list local_ap;

        ptr = buf->data + buf->skip + buf->len;
        free_space = sircc_buf_free_space(buf);

        va_copy(local_ap, ap);
        ret = vsnprintf(ptr, free_space, fmt, local_ap);
        if (ret == -1) {
            sircc_set_error("cannot format string in membuf: %m");
            return -1;
        }
        va_end(local_ap);

        if ((size_t)ret < free_space) {
            buf->len += (size_t)ret;
            return 0;
        }

        sircc_buf_ensure_free_space(buf, (size_t)ret + 1);
    }
}

int
sircc_buf_add_printf(struct sircc_buf *buf, const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    if (sircc_buf_add_vprintf(buf, fmt, ap) == -1)
        return -1;
    va_end(ap);

    return 0;
}

void
sircc_buf_skip(struct sircc_buf *buf, size_t n) {
    if (n > buf->len)
        n = buf->len;

    buf->skip += n;
    buf->len -= n;
}

void
sircc_buf_remove(struct sircc_buf *buf, size_t n) {
    if (n > buf->len)
        n = buf->len;

    buf->len -= n;
}

char *
sircc_buf_dup(const struct sircc_buf *buf) {
    char *tmp;

    if (!buf->data || buf->len == 0) {
        sircc_set_error("cannot duplicate an empty buffer");
        return NULL;
    }

    tmp = malloc(buf->len);
    if (!tmp) {
        sircc_set_error("cannot allocate buffer: %m");
        return NULL;
    }

    memcpy(tmp, buf->data + buf->skip, buf->len);
    return tmp;
}

char *
sircc_buf_dup_str(const struct sircc_buf *buf) {
    char *str;

    str = malloc(buf->len + 1);
    if (!str) {
        sircc_set_error("cannot allocate string: %m");
        return NULL;
    }

    if (buf->data)
        memcpy(str, buf->data + buf->skip, buf->len);
    str[buf->len] = '\0';

    return str;
}

ssize_t
sircc_buf_read(struct sircc_buf *buf, int fd, size_t n) {
    ssize_t ret;
    char *ptr;

    sircc_buf_ensure_free_space(buf, n);

    ptr = buf->data + buf->skip + buf->len;

    ret = read(fd, ptr, n);
    if (ret > 0)
        buf->len += (size_t)ret;

    return ret;
}

ssize_t
sircc_buf_write(struct sircc_buf *buf, int fd) {
    ssize_t ret;

    ret = write(fd, buf->data + buf->skip, buf->len);
    if (ret > 0)
        buf->len -= (size_t)ret;

    return ret;
}
