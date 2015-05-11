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

static void sircc_msg_add_param(struct sircc_msg *, char *);

void
sircc_msg_free(struct sircc_msg *msg) {
    if (!msg)
        return;

    sircc_free(msg->prefix);
    sircc_free(msg->command);

    for (size_t i = 0; i < msg->nb_params; i++)
        sircc_free(msg->params[i]);
    sircc_free(msg->params);
}

int
sircc_msg_parse(struct sircc_msg *msg, struct c_buffer *buf) {
    const char *start, *ptr;
    const char *space, *cr;
    size_t len, toklen;

    len = c_buffer_length(buf);
    ptr = c_buffer_data(buf);

    start = ptr;

    if (len == 0)
        return 0;

    memset(msg, 0, sizeof(struct sircc_msg));

    cr = memchr(ptr, '\r', len);
    if (!cr)
        goto needmore;

    /* The znc.in/server-time CAP extension prefixes messages with a
     * timestamp. In theory, we should only accept this prefix is we
     * successfully activated the extension for the current connection. In
     * practice, parsing and using it in any case should not cause any
     * problem. */
    if (*ptr == '@') {
        const char *dot;

        /* There is a timestamp prefix.
         *
         * The ZNC documentation describes the format as '@t=<timestamp>', but
         * it is in fact '@time=<timestamp>.<msec>' */

        /* Skip the prefix */
        len--;
        if (len == 0)
            goto needmore;
        ptr++;

        if (len < 5)
            goto needmore;
        if (memcmp(ptr, "time=", 5) != 0) {
            sircc_set_error("invalid key in timestamp prefix");
            goto error;
        }
        len -= 5;
        ptr += 5;

        /* Read the timestamp */
        dot = memchr(ptr, '.', len);
        if (!dot)
            goto needmore;

        errno = 0;
        msg->server_date = strtol(ptr, NULL, 10);
        if (errno) {
            sircc_set_error("invalid value in timestamp prefix");
            goto error;
        }

        /* Skip the millisecond part (this kind of precision is useless) */
        space = memchr(ptr, ' ', len);
        if (!space)
            goto needmore;

        len -= (size_t)(space - ptr + 1);
        ptr = space + 1;
    }

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
        msg->prefix = c_strndup(ptr, toklen);

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
        msg->command = c_strndup(ptr, toklen);

        len -= toklen + 1;
        ptr = space + 1;
    } else {
        /* No parameter */
        if (cr - ptr == 0) {
            sircc_set_error("empty command");
            goto error;
        }

        toklen = (size_t)(cr - ptr);
        msg->command = c_strndup(ptr, toklen);

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

            toklen = (size_t)(cr - ptr);
            param = c_strndup(ptr, toklen);
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
                param = c_strndup(ptr, toklen);
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
                param = c_strndup(ptr, toklen);
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

int
sircc_msg_prefix_nickname(const struct sircc_msg *msg,
                          char *buf, size_t bufsz) {
    size_t len;

    if (!msg->prefix) {
        sircc_set_error("no prefix in message");
        return -1;
    }

    len = strcspn(msg->prefix, "!@");
    if (len >= bufsz) {
        sircc_set_error("nickname buffer too small");
        return -1;
    }

    memcpy(buf, msg->prefix, len);
    buf[len] = '\0';
    return 0;
}

bool
sircc_irc_is_chan_prefix(int c) {
    return c == '&'  /* local */
        || c == '#'  /* network */
        || c == '!'  /* network + safe */
        || c == '+'; /* network + unmoderated */
}

struct sircc_irc_cap *
sircc_irc_caps_parse(const char *str, size_t *nb_caps) {
    struct sircc_irc_cap *caps;
    size_t caps_sz;
    const char *ptr;

    caps = NULL;
    caps_sz = 0;

    ptr = str;
    while (*ptr != '\0') {
        const char *space;
        size_t toklen;
        struct sircc_irc_cap *cap;

        while (*ptr == ' ')
            ptr++;

        space = strchr(ptr, ' ');
        if (space) {
            toklen = (size_t)(space - ptr);
        } else {
            toklen = strlen(ptr);
        }

        if (caps_sz == 0) {
            caps_sz = 1;
            caps = sircc_malloc(sizeof(struct sircc_irc_cap));
        } else {
            caps_sz++;
            caps = sircc_realloc(caps, caps_sz * sizeof(struct sircc_irc_cap));
        }

        cap = caps + caps_sz - 1;
        memset(cap, 0, sizeof(struct sircc_irc_cap));

        if (*ptr == '-') {
            caps->modifier = SIRCC_CAP_DISABLE;
        } else if (*ptr == '~') {
            caps->modifier = SIRCC_CAP_ACK;
        } else if (*ptr == '=') {
            caps->modifier = SIRCC_CAP_STICKY;
        } else {
            cap->modifier = SIRCC_CAP_NONE;
        }

        if (cap->modifier == SIRCC_CAP_NONE) {
            cap->name = c_strndup(ptr, toklen);
        } else {
            cap->name = c_strndup(ptr + 1, toklen - 1);
        }

        ptr += toklen;
    }

    *nb_caps = caps_sz;
    return caps;
}

void
sircc_irc_caps_free(struct sircc_irc_cap *caps, size_t nb_caps) {
    for (size_t i = 0; i < nb_caps; i++)
        sircc_free(caps[i].name);
    sircc_free(caps);
}

char *
sircc_ctcp_quote(const char *str) {
    char *nstr, *nptr;
    size_t nsz;

    nsz = 0;
    for (const char *ptr = str; *ptr != '\0'; ptr++) {
        nsz++;

        if (*ptr == '\001' || *ptr == '\134')
            nsz++;
    }

    nstr = sircc_malloc(nsz + 1);
    nptr = nstr;

    for (const char *ptr = str; *ptr != '\0'; ptr++) {
        if (*ptr == '\001') {
            *nptr++ = '\134';
            *nptr++ = 'a';
        } else if (*ptr == '\134') {
            *nptr++ = '\134';
            *nptr++ = '\134';
        } else {
            *nptr++ = *ptr;
        }
    }

    *nptr = '\0';
    return nstr;
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
