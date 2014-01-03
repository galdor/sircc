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

typedef void (*sircc_msg_handler)(struct sircc_server *, struct sircc_msg *);

static void sircc_set_msg_handler(const char *, sircc_msg_handler);

static void sircc_msgh_join(struct sircc_server *, struct sircc_msg *);
static void sircc_msgh_part(struct sircc_server *, struct sircc_msg *);
static void sircc_msgh_ping(struct sircc_server *, struct sircc_msg *);
static void sircc_msgh_privmsg(struct sircc_server *, struct sircc_msg *);
static void sircc_msgh_topic(struct sircc_server *, struct sircc_msg *);
static void sircc_msgh_rpl_welcome(struct sircc_server *, struct sircc_msg *);
static void sircc_msgh_rpl_notopic(struct sircc_server *, struct sircc_msg *);
static void sircc_msgh_rpl_topic(struct sircc_server *, struct sircc_msg *);
static void sircc_msgh_rpl_topicwhotime(struct sircc_server *, struct sircc_msg *);

void
sircc_init_msg_handlers(void) {
    sircc_set_msg_handler("JOIN", sircc_msgh_join);
    sircc_set_msg_handler("PART", sircc_msgh_part);
    sircc_set_msg_handler("PING", sircc_msgh_ping);
    sircc_set_msg_handler("PRIVMSG", sircc_msgh_privmsg);
    sircc_set_msg_handler("TOPIC", sircc_msgh_topic);
    sircc_set_msg_handler("001", sircc_msgh_rpl_welcome);
    sircc_set_msg_handler("331", sircc_msgh_rpl_notopic);
    sircc_set_msg_handler("332", sircc_msgh_rpl_topic);
    sircc_set_msg_handler("333", sircc_msgh_rpl_topicwhotime); /* non-standard */
}

static void
sircc_set_msg_handler(const char *command, sircc_msg_handler handler) {
    ht_table_insert(sircc.msg_handlers, (void *)command, handler);
}

void
sircc_call_msg_handler(struct sircc_server *server, struct sircc_msg *msg) {
    sircc_msg_handler handler;

    if (ht_table_get(sircc.msg_handlers, msg->command,
                     (void **)&handler) == 0) {
        return;
    }

    handler(server, msg);
}

static void
sircc_msgh_join(struct sircc_server *server, struct sircc_msg *msg) {
    struct sircc_chan *chan;
    const char *chan_name;
    char nickname[SIRCC_NICKNAME_MAXSZ];

    if (msg->nb_params < 1) {
        sircc_server_log_error(server, "missing argument in JOIN message");
        return;
    }

    if (sircc_msg_prefix_nickname(msg, nickname, sizeof(nickname)) == -1) {
        sircc_server_log_error(server, "cannot get message nickname: %s",
                               sircc_get_error());
        return;
    }

    chan_name = msg->params[0];
    chan = sircc_server_get_chan(server, chan_name);
    if (!chan) {
        chan = sircc_chan_new(server, chan_name);
        sircc_server_add_chan(server, chan);
    }

    if (strcmp(nickname, server->nickname) == 0) {
        /* We just joined the chan */
        sircc_chan_log_info(chan, "you have joined %s", chan_name);
        sircc_ui_server_select_chan(server, chan);
    } else {
        /* Someone else joined the chan */
        sircc_chan_log_info(chan, "%s has joined %s", nickname, chan_name);
    }
}

static void
sircc_msgh_part(struct sircc_server *server, struct sircc_msg *msg) {
    struct sircc_chan *chan;
    const char *chan_name;
    char nickname[SIRCC_NICKNAME_MAXSZ];

    if (msg->nb_params < 1) {
        sircc_server_log_error(server, "missing argument in PART message");
        return;
    }

    if (sircc_msg_prefix_nickname(msg, nickname, sizeof(nickname)) == -1) {
        sircc_server_log_error(server, "cannot get message nickname: %s",
                               sircc_get_error());
        return;
    }

    chan_name = msg->params[0];
    chan = sircc_server_get_chan(server, chan_name);
    if (!chan) {
        chan = sircc_chan_new(server, chan_name);
        sircc_server_add_chan(server, chan);
    }

    if (strcmp(nickname, server->nickname) == 0) {
        /* We just left the chan */
        sircc_server_remove_chan(server, chan);
        sircc_chan_delete(chan);
    } else {
        /* Someone else left the chan */
        if (msg->nb_params > 1 && msg->params[1] != '\0') {
            sircc_chan_log_info(chan, "%s has left %s: %s",
                                nickname, chan_name, msg->params[1]);
        } else {
            sircc_chan_log_info(chan, "%s has left %s",
                                nickname, chan_name);
        }
    }
}

static void
sircc_msgh_ping(struct sircc_server *server, struct sircc_msg *msg) {
    if (msg->nb_params < 1) {
        sircc_server_log_error(server, "missing argument in PING message");
        return;
    }

    sircc_server_printf(server, "PONG :%s\r\n", msg->params[0]);
}

static void
sircc_msgh_privmsg(struct sircc_server *server, struct sircc_msg *msg) {
    char nickname[SIRCC_NICKNAME_MAXSZ];
    const char *target, *text;
    struct sircc_chan *chan;
    const char *chan_name;

    if (msg->nb_params < 2) {
        sircc_server_log_error(server, "missing arguments in PRIVMSG message");
        return;
    }

    if (sircc_msg_prefix_nickname(msg, nickname, sizeof(nickname)) == -1) {
        sircc_server_log_error(server, "cannot get message nickname: %s",
                               sircc_get_error());
        return;
    }

    target = msg->params[0];
    text = msg->params[1];

    if (sircc_irc_is_chan_prefix(target[0])) {
        /* Public message */
        chan_name = target;
    } else {
        /* Private message */
        chan_name = nickname;
    }

    chan = sircc_server_get_chan(server, chan_name);
    if (!chan) {
        chan = sircc_chan_new(server, chan_name);
        sircc_server_add_chan(server, chan);
    }

    sircc_chan_add_msg(chan, nickname, text);
}

static void
sircc_msgh_topic(struct sircc_server *server, struct sircc_msg *msg) {
    struct sircc_chan *chan;
    const char *chan_name, *topic;
    char nickname[SIRCC_NICKNAME_MAXSZ];

    if (msg->nb_params < 2) {
        sircc_server_log_error(server, "missing arguments in TOPIC message");
        return;
    }

    if (sircc_msg_prefix_nickname(msg, nickname, sizeof(nickname)) == -1) {
        sircc_server_log_error(server, "cannot get message nickname: %s",
                               sircc_get_error());
        return;
    }

    chan_name = msg->params[0];
    topic = msg->params[1];

    chan = sircc_server_get_chan(server, chan_name);
    if (!chan) {
        sircc_server_log_error(server, "unknown chan '%s' in TOPIC message",
                               chan_name);
        return;
    }

    sircc_chan_set_topic(chan, topic);
    sircc_chan_log_info(chan, "%s changed the topic of %s to: %s",
                        nickname, chan_name, topic);
}

static void
sircc_msgh_rpl_welcome(struct sircc_server *server, struct sircc_msg *msg) {
    sircc_server_log_info(server, "registered");

    /* XXX debug */
    sircc_server_printf(server, "JOIN #test\r\n");
}

static void
sircc_msgh_rpl_notopic(struct sircc_server *server, struct sircc_msg *msg) {
    struct sircc_chan *chan;
    const char *chan_name;

    if (msg->nb_params < 2) {
        sircc_server_log_error(server,
                               "missing arguments in RPL_NOTOPIC message");
        return;
    }

    chan_name = msg->params[1];
    chan = sircc_server_get_chan(server, chan_name);
    if (!chan) {
        sircc_server_log_error(server,
                               "unknown chan '%s' in RPL_NOTOPIC message",
                               chan_name);
        return;
    }

    sircc_chan_set_topic(chan, NULL);

    sircc_chan_log_info(chan, "no topic for channel %s", chan_name);
}

static void
sircc_msgh_rpl_topic(struct sircc_server *server, struct sircc_msg *msg) {
    struct sircc_chan *chan;
    const char *chan_name, *topic;

    if (msg->nb_params < 3) {
        sircc_server_log_error(server,
                               "missing arguments in RPL_TOPIC message");
        return;
    }

    chan_name = msg->params[1];
    topic = msg->params[2];

    chan = sircc_server_get_chan(server, chan_name);
    if (!chan) {
        sircc_server_log_error(server,
                               "unknown chan '%s' in RPL_TOPIC message",
                               chan_name);
        return;
    }

    sircc_chan_set_topic(chan, topic);

    sircc_chan_log_info(chan, "topic of channel %s: %s", chan_name, topic);
}

static void
sircc_msgh_rpl_topicwhotime(struct sircc_server *server,
                              struct sircc_msg *msg) {
    struct sircc_chan *chan;
    const char *chan_name, *nickname, *timestamp;
    struct tm tm;
    char date[32];

    if (msg->nb_params < 4) {
        sircc_server_log_error(server, "missing arguments in RPL_TOPICWHOTIME"
                               " message");
        return;
    }

    chan_name = msg->params[1];
    nickname = msg->params[2];
    timestamp = msg->params[3];

    chan = sircc_server_get_chan(server, chan_name);
    if (!chan) {
        sircc_server_log_error(server,
                               "unknown chan '%s' in RPL_TOPICWHOTIME message",
                               chan_name);
        return;
    }

    if (!strptime(timestamp, "%s", &tm)) {
        sircc_server_log_error(server, "invalid timestamp format in"
                               " RPL_TOPICWHOTIME message");
        return;
    }

    strftime(date, sizeof(date), "%F %T %z", &tm);

    sircc_chan_log_info(chan, "topic of channel %s set by %s on %s",
                        chan_name, nickname, date);
}
