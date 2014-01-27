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
    const char *help;
};

static void sircc_cmd_add_arg(struct sircc_cmd *, char *);
static int sircc_cmd_parse_arg(const char **, size_t *, char **);

static struct sircc_cmd_desc *sircc_cmd_get_desc(const char *);

static void sircc_cmdh_help(struct sircc_server *, struct sircc_cmd *);
static void sircc_cmdh_join(struct sircc_server *, struct sircc_cmd *);
static void sircc_cmdh_me(struct sircc_server *, struct sircc_cmd *);
static void sircc_cmdh_mode(struct sircc_server *, struct sircc_cmd *);
static void sircc_cmdh_msg(struct sircc_server *, struct sircc_cmd *);
static void sircc_cmdh_names(struct sircc_server *, struct sircc_cmd *);
static void sircc_cmdh_nick(struct sircc_server *, struct sircc_cmd *);
static void sircc_cmdh_part(struct sircc_server *, struct sircc_cmd *);
static void sircc_cmdh_quit(struct sircc_server *, struct sircc_cmd *);
static void sircc_cmdh_quote(struct sircc_server *, struct sircc_cmd *);
static void sircc_cmdh_topic(struct sircc_server *, struct sircc_cmd *);

static struct sircc_cmd_desc
sircc_cmd_descs[SIRCC_CMD_COUNT] = {
    {"help",  SIRCC_CMD_HELP,  SIRCC_CMD_ARGS_RANGE,      1, 1,
        sircc_cmdh_help,  "/help <command>",
        "display help about a command"},
    {"join",  SIRCC_CMD_JOIN,  SIRCC_CMD_ARGS_RANGE,      1, 2,
        sircc_cmdh_join,  "/join <chan> [<key>]",
        "join a new channel"},
    {"me",    SIRCC_CMD_ME,    SIRCC_CMD_ARGS_TRAILING,   0, 0,
        sircc_cmdh_me,    "/me [<message...>]",
        "send a CTCP action message to a user or channel"},
    {"mode",  SIRCC_CMD_MODE,  SIRCC_CMD_ARGS_TRAILING,   2, 2,
        sircc_cmdh_mode,  "/mode <target> <flags> [<parameters...>]",
        "change the mode flags of a user or channel"},
    {"msg",   SIRCC_CMD_MSG,   SIRCC_CMD_ARGS_TRAILING,   1, 2,
        sircc_cmdh_msg,   "/msg <target> <message...>",
        "send a message to a user or channel"},
    {"names", SIRCC_CMD_NAMES, SIRCC_CMD_ARGS_RANGE,      0, 0,
        sircc_cmdh_names,  "/names",
        "display the list of users in the current channel"},
    {"nick",  SIRCC_CMD_NICK,  SIRCC_CMD_ARGS_RANGE,      1, 1,
        sircc_cmdh_nick,   "/nick <nickname>",
        "change the current nickname"},
    {"part",  SIRCC_CMD_PART,  SIRCC_CMD_ARGS_TRAILING,   0, 0,
        sircc_cmdh_part,  "/part [<message...>]",
        "leave the current channel or private chat"},
    {"quit",  SIRCC_CMD_QUIT,  SIRCC_CMD_ARGS_RANGE,      0, 0,
        sircc_cmdh_quit,  "/quit",
        "quit sircc"},
    {"quote", SIRCC_CMD_QUOTE, SIRCC_CMD_ARGS_TRAILING,   0, 1,
        sircc_cmdh_quote, "/quote <command...>",
        "send a command to the server without any processing"},
    {"topic", SIRCC_CMD_TOPIC, SIRCC_CMD_ARGS_TRAILING,   0, 0,
        sircc_cmdh_topic, "/topic [<message...>]",
        "if an argument is provided, change the topic of the current channel"
        "; if not, display the topic of the current channel"},
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

    ptr = sircc_buf_data(buf);
    len = sircc_buf_length(buf);

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

char *
sircc_cmd_next_completion(const char *prefix, const char *last_completion) {
    const char *first_match;
    size_t prefix_len;

    prefix_len = strlen(prefix);

    first_match = NULL;

    for (size_t i = 0; i < SIRCC_CMD_COUNT; i++) {
        const char *cmd;

        cmd = sircc_cmd_descs[i].name;

        if (strlen(cmd) + 1 >= prefix_len
            && memcmp(cmd, prefix + 1, prefix_len - 1) == 0) {
            if (!first_match)
                first_match = cmd;

            if (!last_completion || strcmp(cmd, last_completion + 1) == 0) {
                const char *next_completion;
                const char *next_cmd;
                char *completion;

                if (i < SIRCC_CMD_COUNT - 1)
                    next_cmd = sircc_cmd_descs[i + 1].name;

                if (i < SIRCC_CMD_COUNT - 1
                    && strlen(next_cmd) + 1 >= prefix_len
                    && memcmp(next_cmd, prefix + 1, prefix_len - 1) == 0) {
                    next_completion = next_cmd;
                } else {
                    next_completion = first_match;
                }

                sircc_asprintf(&completion, "/%s", next_completion);
                return completion;
            }
        }
    }

    return NULL;
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
sircc_cmdh_help(struct sircc_server *server, struct sircc_cmd *cmd) {
    const char *cmd_name;
    struct sircc_cmd_desc *cmd_desc;

    cmd_name = cmd->args[0];

    cmd_desc = sircc_cmd_get_desc(cmd_name);
    if (!cmd_desc) {
        sircc_chan_log_error(server->current_chan, "unknown command '%s'",
                             cmd_name);
        return;
    }

    sircc_chan_log_info(server->current_chan, "%s", cmd_desc->usage);
    sircc_chan_log_info(server->current_chan, "%s", cmd_desc->help);
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
sircc_cmdh_me(struct sircc_server *server, struct sircc_cmd *cmd) {
    struct sircc_chan *chan;
    const char *text;
    time_t now;

    if (cmd->nb_args > 0) {
        text = cmd->args[0];
    } else {
        text = "";
    }

    chan = server->current_chan;
    if (!chan) {
        sircc_chan_log_error(NULL, "no channel selected");
        return;
    }

    sircc_server_printf(server, "PRIVMSG %s :\001ACTION %s\001\r\n",
                        chan->name, text);

    now = time(NULL);
    sircc_chan_add_action(chan, now, server->current_nickname, text);
}

static void
sircc_cmdh_mode(struct sircc_server *server, struct sircc_cmd *cmd) {
    const char *target, *flags;

    target = cmd->args[0];
    flags = cmd->args[1];

    if (cmd->nb_args > 2) {
        sircc_server_printf(server, "MODE %s %s :%s\r\n",
                            target, flags, cmd->args[2]);
    } else {
        sircc_server_printf(server, "MODE %s %s\r\n",
                            target, flags);
    }
}

static void
sircc_cmdh_msg(struct sircc_server *server, struct sircc_cmd *cmd) {
    const char *target, *text;
    struct sircc_chan *chan;
    time_t now;

    target = cmd->args[0];
    text = cmd->args[1];

    chan = sircc_server_get_chan(server, target);
    if (!chan) {
        chan = sircc_chan_new(server, target);
        sircc_server_add_chan(server, chan);
        sircc_ui_server_select_chan(server, chan);
    }

    sircc_server_printf(server, "PRIVMSG %s :%s\r\n", target, text);

    now = time(NULL);
    sircc_chan_add_msg(chan, now, server->current_nickname, text);
}

static void
sircc_cmdh_names(struct sircc_server *server, struct sircc_cmd *cmd) {
    struct sircc_chan *chan;

    chan = server->current_chan;
    if (chan) {
        if (chan->is_user) {
            sircc_chan_log_error(NULL, "private discussions have no user list");
            return;
        }

        sircc_server_printf(server, "NAMES %s\r\n", chan->name);
    } else {
        sircc_server_printf(server, "NAMES\r\n");
    }
}

static void
sircc_cmdh_nick(struct sircc_server *server, struct sircc_cmd *cmd) {
    sircc_server_printf(server, "NICK %s\r\n", cmd->args[0]);
}

static void
sircc_cmdh_part(struct sircc_server *server, struct sircc_cmd *cmd) {
    struct sircc_chan *chan;

    chan = server->current_chan;
    if (!chan) {
        sircc_server_log_error(server, "no channel selected");
        return;
    }

    if (chan->is_user) {
        /* While using /part on a user chan is invalid, the right thing to do
         * is to just close the chan. */
        sircc_server_remove_chan(server, chan);
        sircc_chan_delete(chan);
    } else {
        if (cmd->nb_args == 0) {
            sircc_server_printf(server, "PART %s\r\n",
                                chan->name);
        } else {
            sircc_server_printf(server, "PART %s :%s\r\n",
                                chan->name, cmd->args[0]);
        }
    }
}

static void
sircc_cmdh_quit(struct sircc_server *server, struct sircc_cmd *cmd) {
    sircc.do_exit = true;
}

static void
sircc_cmdh_quote(struct sircc_server *server, struct sircc_cmd *cmd) {
    sircc_server_printf(server, "%s\r\n", cmd->args[0]);
}

static void
sircc_cmdh_topic(struct sircc_server *server, struct sircc_cmd *cmd) {
    struct sircc_chan *chan;

    chan = server->current_chan;
    if (!chan) {
        sircc_chan_log_error(NULL, "no channel selected");
        return;
    }

    if (chan->is_user) {
        sircc_chan_log_error(NULL, "private discussions have no topic");
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
