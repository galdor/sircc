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

#include "sircc.h"

enum sircc_cmd_args_fmt {
    SIRCC_CMD_ARGS_RANGE,    /* X to Y args */
    SIRCC_CMD_ARGS_TRAILING, /* X args + trailing */
};

typedef void (*sircc_cmd_handler)(struct sircc_server *, struct sircc_cmd *);

/* ARGS_RANGE:    the command must have between 'min' and 'max' arguments.
 * ARGS_TRAILING: the command must have 'min' arguments. If 'max' is
 *                equal to 'min', the trailing argument is optional.
 *                If it is greater than 'min', it is mandatory. */
struct sircc_cmd_desc {
    const char *name;
    enum sircc_cmd_id cmd;
    enum sircc_cmd_args_fmt args_fmt;
    size_t min, max;
    sircc_cmd_handler handler;
    const char *usage;
};

static void sircc_cmd_add_arg(struct sircc_cmd *, char *);
static int sircc_cmd_parse_arg(const char **, size_t *, char **);

static struct sircc_cmd_desc *sircc_cmd_get_desc(const char *);

static void sircc_cmdh_join(struct sircc_server *, struct sircc_cmd *);
static void sircc_cmdh_msg(struct sircc_server *, struct sircc_cmd *);
static void sircc_cmdh_names(struct sircc_server *, struct sircc_cmd *);
static void sircc_cmdh_part(struct sircc_server *, struct sircc_cmd *);
static void sircc_cmdh_quit(struct sircc_server *, struct sircc_cmd *);
static void sircc_cmdh_topic(struct sircc_server *, struct sircc_cmd *);

static struct sircc_cmd_desc
sircc_cmd_descs[SIRCC_CMD_COUNT] = {
    {"join",  SIRCC_CMD_JOIN,  SIRCC_CMD_ARGS_RANGE,      1, 2,
        sircc_cmdh_join,  "/join <chan> [<key>]"},
    {"msg",   SIRCC_CMD_MSG,   SIRCC_CMD_ARGS_TRAILING,   1, 2,
        sircc_cmdh_msg,   "/msg <target> <message...>"},
    {"names", SIRCC_CMD_NAMES, SIRCC_CMD_ARGS_RANGE,      0, 0,
        sircc_cmdh_names,  "/names"},
    {"part",  SIRCC_CMD_PART,  SIRCC_CMD_ARGS_TRAILING,   0, 0,
        sircc_cmdh_part,  "/part <chan> [<message...>]"},
    {"quit",  SIRCC_CMD_QUIT,  SIRCC_CMD_ARGS_RANGE,      0, 0,
        sircc_cmdh_quit,  "/quit"},
    {"topic", SIRCC_CMD_TOPIC, SIRCC_CMD_ARGS_TRAILING,   0, 0,
        sircc_cmdh_topic, "/topic [<message...>]"},
};

void
sircc_cmd_free(struct sircc_cmd *cmd) {
    for (size_t i = 0; i < cmd->nb_args; i++)
        sircc_free(cmd->args[i]);
    sircc_free(cmd->args);
}

int
sircc_cmd_parse(struct sircc_cmd *cmd, struct sircc_buf *buf) {
    struct sircc_cmd_desc *desc;
    const char *ptr;
    const char *space;
    size_t len, toklen;
    char *name;

    ptr = sircc_buf_data(&sircc.prompt_buf);
    len = sircc_buf_length(&sircc.prompt_buf);

    memset(cmd, 0, sizeof(struct sircc_cmd));

    if (*ptr != '/') {
        sircc_set_error("missing leading '/'");
        goto error;
    }

    /* Skip '/' */
    ptr++;
    len--;
    if (len == 0)
        goto needmore;

    /* Read the command name */
    space = memchr(ptr, ' ', len);
    if (space) {
        toklen = (size_t)(space - ptr);
    } else {
        toklen = len;
    }

    name = sircc_strndup(ptr, toklen);
    desc = sircc_cmd_get_desc(name);
    if (!desc) {
        sircc_set_error("unknown command '%s'", name);
        sircc_free(name);
        goto error;
    }
    sircc_free(name);

    cmd->id = desc->cmd;

    ptr += toklen;
    len -= toklen;

    /* Read the minimum number of arguments */
    for (size_t i = 0; i < desc->min; i++) {
        char *arg;
        int ret;

        ret = sircc_cmd_parse_arg(&ptr, &len, &arg);
        if (ret == 0) {
            sircc_set_error("missing argument");
            goto error;
        }

        if (ret == 1)
            sircc_cmd_add_arg(cmd, arg);
    }

    switch (desc->args_fmt) {
    case SIRCC_CMD_ARGS_RANGE:
        /* Read the rest of the arguments */
        for (size_t i = 0; i < desc->max - desc->min; i++) {
            char *arg;
            int ret;

            ret = sircc_cmd_parse_arg(&ptr, &len, &arg);
            if (ret == 0)
                break;

            if (ret == 1)
                sircc_cmd_add_arg(cmd, arg);
        }
        break;

    case SIRCC_CMD_ARGS_TRAILING:
        /* Read the trailing argument */
        {
            char *arg;

            /* Skip leading spaces */
            while (len > 0) {
                if (*ptr != ' ')
                    break;

                ptr++;
                len--;
            }

            if (len == 0) {
                if (desc->max == desc->min) {
                    /* The trailing argument is optional */
                    return 1;
                } else {
                    /* The trailing argument is mandatory */
                    sircc_set_error("missing trailing argument");
                    goto error;
                }
            }

            arg = sircc_strndup(ptr, len);
            sircc_cmd_add_arg(cmd, arg);
        }
        break;
    }

    return 1;

needmore:
    sircc_cmd_free(cmd);
    return 0;

error:
    sircc_cmd_free(cmd);
    return -1;
}

void
sircc_cmd_run(struct sircc_cmd *cmd) {
    struct sircc_server *server;
    struct sircc_cmd_desc *desc;

    desc = &sircc_cmd_descs[cmd->id];
    server = sircc_server_get_current();
    desc->handler(server, cmd);
}

static void
sircc_cmd_add_arg(struct sircc_cmd *cmd, char *arg) {
    if (cmd->nb_args == 0) {
        cmd->nb_args = 1;
        cmd->args = sircc_malloc(sizeof(char *));
        cmd->args[0] = arg;
    } else {
        cmd->nb_args++;
        cmd->args = sircc_realloc(cmd->args, cmd->nb_args * sizeof(char *));
        cmd->args[cmd->nb_args - 1] = arg;
    }
}

static int
sircc_cmd_parse_arg(const char **pptr, size_t *plen, char **parg) {
    const char *ptr, *space;
    size_t len, arglen;
    char *arg;

    ptr = *pptr;
    len = *plen;

    /* Skip leading spaces */
    while (len > 0) {
        if (*ptr != ' ')
            break;

        ptr++;
        len--;
    }

    if (len == 0)
        return 0;

    space = memchr(ptr, ' ', len);
    if (space) {
        arglen = (size_t)(space - ptr);
    } else {
        arglen = len;
    }

    arg = sircc_strndup(ptr, arglen);

    ptr += arglen;
    len -= arglen;

    *pptr = ptr;
    *plen = len;
    *parg = arg;

    return 1;
}

static struct sircc_cmd_desc *
sircc_cmd_get_desc(const char *name) {
    size_t nb_descs;

    nb_descs = sizeof(sircc_cmd_descs) / sizeof(struct sircc_cmd_desc);

    for (size_t i = 0; i < nb_descs; i++) {
        if (strcmp(name, sircc_cmd_descs[i].name) == 0)
            return &sircc_cmd_descs[i];
    }

    return NULL;
}

static void
sircc_cmdh_join(struct sircc_server *server, struct sircc_cmd *cmd) {
    if (cmd->nb_args > 1) {
        sircc_server_printf(server, "JOIN %s %s\r\n",
                            cmd->args[0], cmd->args[1]);
    } else {
        sircc_server_printf(server, "JOIN %s\r\n",
                            cmd->args[0]);
    }
}

static void
sircc_cmdh_msg(struct sircc_server *server, struct sircc_cmd *cmd) {
    /* TODO */
}

static void
sircc_cmdh_names(struct sircc_server *server, struct sircc_cmd *cmd) {
    struct sircc_chan *chan;

    chan = server->current_chan;
    if (chan) {
        sircc_server_printf(server, "NAMES %s\r\n", chan->name);
    } else {
        sircc_server_printf(server, "NAMES\r\n");
    }
}

static void
sircc_cmdh_part(struct sircc_server *server, struct sircc_cmd *cmd) {
    struct sircc_chan *chan;

    chan = server->current_chan;
    if (!chan) {
        sircc_server_log_error(server, "no channel selected");
        return;
    }

    if (cmd->nb_args == 0) {
        sircc_server_printf(server, "PART %s\r\n",
                            chan->name);
    } else {
        sircc_server_printf(server, "PART %s :%s\r\n",
                            chan->name, cmd->args[0]);
    }
}

static void
sircc_cmdh_quit(struct sircc_server *server, struct sircc_cmd *cmd) {
    sircc.do_exit = true;
}

static void
sircc_cmdh_topic(struct sircc_server *server, struct sircc_cmd *cmd) {
    struct sircc_chan *chan;

    chan = server->current_chan;
    if (!chan) {
        sircc_server_log_error(server, "no channel selected");
        return;
    }

    if (cmd->args == 0) {
        sircc_server_printf(server, "TOPIC %s\r\n",
                            chan->name);
    } else {
        sircc_server_printf(server, "TOPIC %s :%s\r\n",
                            chan->name, cmd->args[0]);
    }
}
