/*
 * Copyright (c) 2013 Nicolas Martyanoff
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

#include <string.h>

#include "sircc.h"

static void sircc_msg_add_param(struct sircc_msg *, char *);

void
sircc_msg_free(struct sircc_msg *msg) {
    if (!msg)
        return;

    free(msg->prefix);
    free(msg->command);

    for (size_t i = 0; i < msg->nb_params; i++)
        free(msg->params[i]);
    free(msg->params);
}

int
sircc_msg_parse(struct sircc_msg *msg, struct sircc_buf *buf) {
    const char *start, *ptr;
    const char *space, *cr;
    size_t len, toklen;

    len = sircc_buf_length(buf);
    ptr = sircc_buf_data(buf);

    start = ptr;

    if (len == 0)
        return 0;

    memset(msg, 0, sizeof(struct sircc_msg));

    cr = memchr(ptr, '\r', len);
    if (!cr)
        goto needmore;

    if (*ptr == ':') {
        /* There is a prefix */
        len--;
        if (len == 0)
            goto needmore;
        ptr++;

        space = memchr(ptr, ' ', len);
        if (!space)
            goto needmore;

        if (space - ptr == 0) {
            sircc_set_error("empty prefix");
            goto error;
        }

        toklen = (size_t)(space - ptr);
        msg->prefix = sircc_strndup(ptr, toklen);

        len -= toklen + 1;
        ptr = space + 1;
    }

    /* Search for the end of the command */
    space = memchr(ptr, ' ', len);
    if (space && space < cr) {
        if (space - ptr == 0) {
            sircc_set_error("empty command");
            goto error;
        }

        toklen = (size_t)(space - ptr);
        msg->command = sircc_strndup(ptr, toklen);

        len -= toklen + 1;
        ptr = space + 1;
    } else {
        /* No parameter */
        if (cr - ptr == 0) {
            sircc_set_error("empty command");
            goto error;
        }

        toklen = (size_t)(cr - ptr);
        msg->command = sircc_strndup(ptr, toklen);

        len -= toklen;
        ptr = cr;
        goto checkcrlf;
    }

    /* Read parameters */
    for (;;) {
        char *param;

        if (len == 0)
            goto needmore;

        if (*ptr == ':') {
            /* Trailing parameter */
            len--;
            if (len == 0)
                goto needmore;
            ptr++;

            if (cr - ptr == 0) {
                sircc_set_error("empty trailing parameter");
                goto error;
            }

            toklen = (size_t)(cr - ptr);
            param = sircc_strndup(ptr, toklen);
            sircc_msg_add_param(msg, param);

            len -= toklen;
            ptr = cr;
            goto checkcrlf;
        } else {
            /* Middle parameter */
            space = memchr(ptr, ' ', len);
            if (space && space < cr) {
                if (space - ptr == 0) {
                    sircc_set_error("empty parameter");
                    goto error;
                }

                toklen = (size_t)(space - ptr);
                param = sircc_strndup(ptr, toklen);
                sircc_msg_add_param(msg, param);

                len -= toklen + 1;
                ptr = space + 1;
            } else {
                /* Last parameter */
                if (cr - ptr == 0) {
                    sircc_set_error("empty parameter");
                    goto error;
                }

                toklen = (size_t)(cr - ptr);
                param = sircc_strndup(ptr, toklen);
                sircc_msg_add_param(msg, param);

                len -= toklen;
                ptr = cr;
                goto checkcrlf;
            }
        }
    }

    return 0;

checkcrlf:
    if (len == 0)
        goto needmore;
    if (*ptr != '\r') {
        sircc_set_error("missing \\r");
        goto error;
    }

    len--;
    if (len == 0)
        goto needmore;
    ptr++;

    if (*ptr != '\n') {
        sircc_set_error("missing \\n after \\r");
        goto error;
    }
    len--;
    ptr++;

    return ptr - start;

needmore:
    sircc_msg_free(msg);
    return 0;

error:
    sircc_msg_free(msg);
    return -1;
}

static void
sircc_msg_add_param(struct sircc_msg *msg, char *param) {
    if (!msg->params) {
        msg->nb_params = 1;
        msg->params = sircc_malloc(sizeof(char *));
    } else {
        msg->nb_params++;
        msg->params = sircc_realloc(msg->params,
                                    msg->nb_params * sizeof(char *));
    }

    msg->params[msg->nb_params - 1] = param;
}
