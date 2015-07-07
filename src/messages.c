/*
 * Copyright (c) 2013-2015 Nicolas Martyanoff
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

#define SIRCC_DECLARE_MSG_HANDLER(id_)                                       \
    static void sircc_msgh_##id_(struct sircc_server *, struct sircc_msg *);

SIRCC_DECLARE_MSG_HANDLER(cap);
SIRCC_DECLARE_MSG_HANDLER(cap_ls);
SIRCC_DECLARE_MSG_HANDLER(cap_ack);
SIRCC_DECLARE_MSG_HANDLER(cap_nack);
SIRCC_DECLARE_MSG_HANDLER(join);
SIRCC_DECLARE_MSG_HANDLER(mode);
SIRCC_DECLARE_MSG_HANDLER(nick);
SIRCC_DECLARE_MSG_HANDLER(notice);
SIRCC_DECLARE_MSG_HANDLER(part);
SIRCC_DECLARE_MSG_HANDLER(ping);
SIRCC_DECLARE_MSG_HANDLER(privmsg);
SIRCC_DECLARE_MSG_HANDLER(quit);
SIRCC_DECLARE_MSG_HANDLER(topic);
SIRCC_DECLARE_MSG_HANDLER(rpl_welcome);
SIRCC_DECLARE_MSG_HANDLER(rpl_notopic);
SIRCC_DECLARE_MSG_HANDLER(rpl_topic);
SIRCC_DECLARE_MSG_HANDLER(rpl_topicwhotime);
SIRCC_DECLARE_MSG_HANDLER(rpl_namreply);
SIRCC_DECLARE_MSG_HANDLER(err_nosuchnick);
SIRCC_DECLARE_MSG_HANDLER(err_invalidcapcmd);
SIRCC_DECLARE_MSG_HANDLER(err_notregistered);
SIRCC_DECLARE_MSG_HANDLER(err_passwdmismatch);
SIRCC_DECLARE_MSG_HANDLER(err_unknownmode);
SIRCC_DECLARE_MSG_HANDLER(err_noprivileges);
SIRCC_DECLARE_MSG_HANDLER(err_chanoprivsneeded);
SIRCC_DECLARE_MSG_HANDLER(err_umodeunknownflag);

#undef SIRCC_DECLARE_MSG_HANDLER

void
sircc_init_msg_handlers(void) {
    sircc_set_msg_handler("CAP", sircc_msgh_cap);
    sircc_set_msg_handler("JOIN", sircc_msgh_join);
    sircc_set_msg_handler("MODE", sircc_msgh_mode);
    sircc_set_msg_handler("NICK", sircc_msgh_nick);
    sircc_set_msg_handler("NOTICE", sircc_msgh_notice);
    sircc_set_msg_handler("PART", sircc_msgh_part);
    sircc_set_msg_handler("PING", sircc_msgh_ping);
    sircc_set_msg_handler("PRIVMSG", sircc_msgh_privmsg);
    sircc_set_msg_handler("QUIT", sircc_msgh_quit);
    sircc_set_msg_handler("TOPIC", sircc_msgh_topic);
    sircc_set_msg_handler("001", sircc_msgh_rpl_welcome);
    sircc_set_msg_handler("331", sircc_msgh_rpl_notopic);
    sircc_set_msg_handler("332", sircc_msgh_rpl_topic);
    sircc_set_msg_handler("333", sircc_msgh_rpl_topicwhotime); /* non-standard */
    sircc_set_msg_handler("353", sircc_msgh_rpl_namreply);
    sircc_set_msg_handler("401", sircc_msgh_err_nosuchnick);
    sircc_set_msg_handler("410", sircc_msgh_err_invalidcapcmd);
    sircc_set_msg_handler("451", sircc_msgh_err_notregistered);
    sircc_set_msg_handler("464", sircc_msgh_err_passwdmismatch);
    sircc_set_msg_handler("472", sircc_msgh_err_unknownmode);
    sircc_set_msg_handler("481", sircc_msgh_err_noprivileges);
    sircc_set_msg_handler("482", sircc_msgh_err_chanoprivsneeded);
    sircc_set_msg_handler("501", sircc_msgh_err_umodeunknownflag);
}

static void
sircc_set_msg_handler(const char *command, sircc_msg_handler handler) {
    c_hash_table_insert(sircc.msg_handlers, (void *)command, handler);
}

void
sircc_call_msg_handler(struct sircc_server *server, struct sircc_msg *msg) {
    sircc_msg_handler handler;

    if (c_hash_table_get(sircc.msg_handlers, msg->command,
                     (void **)&handler) == 0) {
        return;
    }

    handler(server, msg);
}

#define SIRCC_MSG_HANDLER(id_)                                           \
    static void                                                          \
    sircc_msgh_##id_(struct sircc_server *server, struct sircc_msg *msg)

SIRCC_MSG_HANDLER(cap) {
    char *subcmd;

    if (msg->nb_params < 2) {
        sircc_server_log_error(server, "missing argument in CAP");
        return;
    }

    subcmd = msg->params[1];

    if (strcmp(subcmd, "LS") == 0) {
        sircc_msgh_cap_ls(server, msg);
    } else if (strcmp(subcmd, "ACK") == 0) {
        sircc_msgh_cap_ack(server, msg);
    } else if (strcmp(subcmd, "NACK") == 0) {
        sircc_msgh_cap_nack(server, msg);
    } else {
        sircc_server_log_error(server, "unknown CAP subcommand '%s'", subcmd);
        return;
    }
}

SIRCC_MSG_HANDLER(cap_ls) {
    const char *caps_str;
    struct sircc_irc_cap *caps;
    size_t nb_caps;

    if (msg->nb_params < 3) {
        sircc_server_log_error(server, "missing argument in CAP LS");
        return;
    }

    caps_str = msg->params[2];

    caps = sircc_irc_caps_parse(caps_str, &nb_caps);
    if (!caps) {
        sircc_server_log_error(server, "cannot parse cap list: %s",
                               c_get_error());
        return;
    }

    for (size_t i = 0; i < nb_caps; i++) {
        struct sircc_irc_cap *cap;

        cap = &caps[i];

        if (strcmp(cap->name, "znc.in/server-time") == 0)
            sircc_server_printf(server, "CAP REQ :%s\r\n", cap->name);
    }

    sircc_irc_caps_free(caps, nb_caps);

    sircc_server_printf(server, "CAP END\r\n");
}

SIRCC_MSG_HANDLER(cap_ack) {
    const char *caps_str;
    struct sircc_irc_cap *caps;
    size_t nb_caps;

    if (msg->nb_params < 3) {
        sircc_server_log_error(server, "missing argument in CAP ACK");
        return;
    }

    caps_str = msg->params[2];

    caps = sircc_irc_caps_parse(caps_str, &nb_caps);
    if (!caps) {
        sircc_server_log_error(server, "cannot parse cap list: %s",
                               c_get_error());
        return;
    }

    for (size_t i = 0; i < nb_caps; i++) {
        struct sircc_irc_cap *cap;

        cap = &caps[i];

        if (strcmp(cap->name, "znc.in/server-time") == 0) {
            sircc_server_log_info(server, "activate cap extension %s",
                                  cap->name);
            server->cap_znc_server_time = true;
        }
    }

    sircc_irc_caps_free(caps, nb_caps);
}

SIRCC_MSG_HANDLER(cap_nack) {
    const char *caps_str;
    struct sircc_irc_cap *caps;
    size_t nb_caps;

    if (msg->nb_params < 3) {
        sircc_server_log_error(server, "missing argument in CAP NACK");
        return;
    }

    caps_str = msg->params[2];

    caps = sircc_irc_caps_parse(caps_str, &nb_caps);
    if (!caps) {
        sircc_server_log_error(server, "cannot parse cap list: %s",
                               c_get_error());
        return;
    }

    for (size_t i = 0; i < nb_caps; i++) {
        struct sircc_irc_cap *cap;

        cap = &caps[i];

        if (strcmp(cap->name, "znc.in/server-time") == 0)
            server->cap_znc_server_time = false;
    }

    sircc_irc_caps_free(caps, nb_caps);
}

SIRCC_MSG_HANDLER(join) {
    struct sircc_chan *chan;
    const char *chan_name;
    char nickname[SIRCC_NICKNAME_MAXSZ];

    if (msg->nb_params < 1) {
        sircc_server_log_error(server, "missing argument in JOIN");
        return;
    }

    if (sircc_msg_prefix_nickname(msg, nickname, sizeof(nickname)) == -1) {
        sircc_server_log_error(server, "cannot get prefix nick: %s",
                               c_get_error());
        return;
    }

    chan_name = msg->params[0];
    chan = sircc_server_get_chan(server, chan_name);
    if (!chan) {
        chan = sircc_chan_new(server, chan_name);
        sircc_server_add_chan(server, chan);
    }

    sircc_chan_add_user(chan, nickname, (size_t)-1);

    if (strcmp(nickname, server->current_nickname) == 0) {
        /* We just joined the chan */
        sircc_chan_log_info(chan, "you have joined %s", chan_name);
        sircc_ui_server_select_chan(server, chan);
    } else {
        /* Someone else joined the chan */
        sircc_chan_log_info(chan, "%s has joined %s", nickname, chan_name);
    }
}

SIRCC_MSG_HANDLER(mode) {
    struct sircc_chan *chan;
    const char *target, *flags;
    char nickname[SIRCC_NICKNAME_MAXSZ];

    if (msg->nb_params < 2) {
        sircc_server_log_error(server, "missing argument in MODE");
        return;
    }

    if (sircc_msg_prefix_nickname(msg, nickname, sizeof(nickname)) == -1) {
        sircc_server_log_error(server, "cannot get prefix nick: %s",
                               c_get_error());
        return;
    }

    target = msg->params[0];
    flags = msg->params[1];

    chan = sircc_server_get_chan(server, target);

    /* We may not have an open channel with the target, for example when
     * receiving a MODE notification for a user which is not on one of our
     * channels. */

    if (msg->nb_params > 2) {
        sircc_chan_log_info(chan, "%s has changed mode for %s to %s %s",
                            nickname, target, flags, msg->params[2]);
    } else {
        sircc_chan_log_info(chan, "%s has changed mode for %s to %s",
                            nickname, target, flags);
    }
}

SIRCC_MSG_HANDLER(nick) {
    const char *new_nickname;
    char nickname[SIRCC_NICKNAME_MAXSZ];

    if (msg->nb_params < 1) {
        sircc_server_log_error(server, "missing argument in NICK");
        return;
    }

    if (sircc_msg_prefix_nickname(msg, nickname, sizeof(nickname)) == -1) {
        sircc_server_log_error(server, "cannot get prefix nick: %s",
                               c_get_error());
        return;
    }

    new_nickname = msg->params[0];

    if (strcmp(server->current_nickname, nickname) == 0) {
        sircc_chan_log_info(server->current_chan,
                            "you changed your nickname to %s",
                            new_nickname);
        c_free(server->current_nickname);
        server->current_nickname = c_strdup(new_nickname);
    } else {
        sircc_chan_log_info(server->current_chan,
                            "%s has changed is nickname to %s",
                            nickname, new_nickname);
    }
}

SIRCC_MSG_HANDLER(notice) {
    char nickname[SIRCC_NICKNAME_MAXSZ];
    const char *target, *text;
    struct sircc_chan *chan;
    const char *chan_name;
    bool log_to_chan;
    time_t date;

    if (msg->nb_params < 2) {
        sircc_server_log_error(server, "missing arguments in NOTICE");
        return;
    }

    if (sircc_msg_prefix_nickname(msg, nickname, sizeof(nickname)) == -1) {
        sircc_server_log_error(server, "cannot get prefix nick: %s",
                               c_get_error());
        return;
    }

    target = msg->params[0];
    text = msg->params[1];

    if (sircc_irc_is_chan_prefix(target[0])) {
        /* Public message */
        log_to_chan = true;
        chan_name = target;
    } else if (strcmp(target, server->current_nickname) == 0) {
        /* Private message */
        log_to_chan = true;
        chan_name = nickname;
    } else {
        /* Private message before registration */
        log_to_chan = false;
    }

    date = (msg->server_date > 0) ? msg->server_date : time(NULL);

    if (log_to_chan) {
        chan = sircc_server_get_chan(server, chan_name);
        if (!chan) {
            chan = sircc_chan_new(server, chan_name);
            sircc_server_add_chan(server, chan);
        }

        sircc_chan_add_server_msg(chan, date, nickname, text);
    } else {
        sircc_server_add_server_msg(server, date, nickname, text);
    }
}

SIRCC_MSG_HANDLER(part) {
    struct sircc_chan *chan;
    const char *chan_name;
    char nickname[SIRCC_NICKNAME_MAXSZ];

    if (msg->nb_params < 1) {
        sircc_server_log_error(server, "missing argument in PART");
        return;
    }

    if (sircc_msg_prefix_nickname(msg, nickname, sizeof(nickname)) == -1) {
        sircc_server_log_error(server, "cannot get prefix nick: %s",
                               c_get_error());
        return;
    }

    chan_name = msg->params[0];
    chan = sircc_server_get_chan(server, chan_name);
    if (!chan) {
        chan = sircc_chan_new(server, chan_name);
        sircc_server_add_chan(server, chan);
    }

    sircc_chan_remove_user(chan, nickname);

    if (strcmp(nickname, server->current_nickname) == 0) {
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

SIRCC_MSG_HANDLER(ping) {
    if (msg->nb_params < 1) {
        sircc_server_log_error(server, "missing argument in PING");
        return;
    }

    sircc_server_printf(server, "PONG :%s\r\n", msg->params[0]);
}

SIRCC_MSG_HANDLER(privmsg) {
    char nickname[SIRCC_NICKNAME_MAXSZ];
    const char *target, *text;
    struct sircc_chan *chan;
    const char *chan_name;
    time_t date;

    if (msg->nb_params < 2) {
        sircc_server_log_error(server, "missing arguments in PRIVMSG");
        return;
    }

    if (sircc_msg_prefix_nickname(msg, nickname, sizeof(nickname)) == -1) {
        sircc_server_log_error(server, "cannot get prefix nick: %s",
                               c_get_error());
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

    date = (msg->server_date > 0) ? msg->server_date : time(NULL);
    sircc_chan_add_msg(chan, date, nickname, text);
}

SIRCC_MSG_HANDLER(quit) {
    char nickname[SIRCC_NICKNAME_MAXSZ];
    const char *text;
    struct sircc_chan *chan;

    if (sircc_msg_prefix_nickname(msg, nickname, sizeof(nickname)) == -1) {
        sircc_server_log_error(server, "cannot get prefix nick: %s",
                               c_get_error());
        return;
    }

    if (msg->nb_params > 0 && msg->params[0] != '\0') {
        text = msg->params[0];
    } else {
        text = NULL;
    }

    chan = server->chans;
    while (chan) {
        if (text) {
            sircc_chan_log_info(chan, "%s has quit", nickname);
        } else {
            sircc_chan_log_info(chan, "%s has quit: %s", nickname, text);
        }

        sircc_chan_remove_user(chan, nickname);

        chan = chan->next;
    }
}

SIRCC_MSG_HANDLER(topic) {
    struct sircc_chan *chan;
    const char *chan_name, *topic;
    char nickname[SIRCC_NICKNAME_MAXSZ];

    if (msg->nb_params < 2) {
        sircc_server_log_error(server, "missing arguments in TOPIC");
        return;
    }

    if (sircc_msg_prefix_nickname(msg, nickname, sizeof(nickname)) == -1) {
        sircc_server_log_error(server, "cannot get prefix nick: %s",
                               c_get_error());
        return;
    }

    chan_name = msg->params[0];
    topic = msg->params[1];

    chan = sircc_server_get_chan(server, chan_name);
    if (!chan) {
        sircc_server_log_error(server, "unknown chan '%s' in TOPIC",
                               chan_name);
        return;
    }

    sircc_chan_set_topic(chan, topic);
    sircc_chan_log_info(chan, "%s changed the topic of %s to: %s",
                        nickname, chan_name, topic);
}

SIRCC_MSG_HANDLER(rpl_welcome) {
    struct c_buffer *buf;

    sircc_server_log_info(server, "irc client registered");

    for (size_t i = 0; i < c_ptr_vector_length(server->auto_join); i++) {
        const char *chan;

        chan = c_ptr_vector_entry(server->auto_join, i);
        sircc_server_printf(server, "JOIN %s\r\n", chan);
    }

    buf = c_buffer_new();

    for (size_t i = 0; i < c_ptr_vector_length(server->auto_commands); i++) {
        const char *string;
        struct sircc_cmd cmd;
        int ret;

        string = c_ptr_vector_entry(server->auto_commands, i);

        c_buffer_clear(buf);
        c_buffer_add_string(buf, string);

        ret = sircc_cmd_parse(&cmd, buf);
        if (ret == -1) {
            sircc_server_log_error(server, "cannot parse auto command '%s': %s",
                                   string, c_get_error());
        } else if (ret == 0) {
            sircc_chan_log_error(NULL, "cannot parse auto command '%s':"
                                 " truncated input", string);
        } else {
            sircc_cmd_run(&cmd);
            sircc_cmd_free(&cmd);
        }
    }

    c_buffer_delete(buf);
}

SIRCC_MSG_HANDLER(rpl_notopic) {
    struct sircc_chan *chan;
    const char *chan_name;

    if (msg->nb_params < 2) {
        sircc_server_log_error(server, "missing arguments in RPL_NOTOPIC");
        return;
    }

    chan_name = msg->params[1];
    chan = sircc_server_get_chan(server, chan_name);
    if (!chan) {
        sircc_server_log_error(server, "unknown chan '%s' in RPL_NOTOPIC",
                               chan_name);
        return;
    }

    sircc_chan_set_topic(chan, NULL);

    sircc_chan_log_info(chan, "no topic for chan %s", chan_name);
}

SIRCC_MSG_HANDLER(rpl_topic) {
    struct sircc_chan *chan;
    const char *chan_name, *topic;

    if (msg->nb_params < 3) {
        sircc_server_log_error(server, "missing arguments in RPL_TOPIC");
        return;
    }

    chan_name = msg->params[1];
    topic = msg->params[2];

    chan = sircc_server_get_chan(server, chan_name);
    if (!chan) {
        sircc_server_log_error(server, "unknown chan '%s' in RPL_TOPIC",
                               chan_name);
        return;
    }

    sircc_chan_set_topic(chan, topic);

    sircc_chan_log_info(chan, "topic of chan %s: %s", chan_name, topic);
}

SIRCC_MSG_HANDLER(rpl_topicwhotime) {
    struct sircc_chan *chan;
    const char *chan_name, *nickname, *timestamp;
    struct tm tm;
    char date[32];

    if (msg->nb_params < 4) {
        sircc_server_log_error(server, "missing arguments in RPL_TOPICWHOTIME");
        return;
    }

    chan_name = msg->params[1];
    nickname = msg->params[2];
    timestamp = msg->params[3];

    chan = sircc_server_get_chan(server, chan_name);
    if (!chan) {
        sircc_server_log_error(server, "unknown chan '%s' in RPL_TOPICWHOTIME",
                               chan_name);
        return;
    }

    if (!strptime(timestamp, "%s", &tm)) {
        sircc_server_log_error(server, "invalid timestamp format in"
                               " RPL_TOPICWHOTIME message");
        return;
    }

    strftime(date, sizeof(date), "%F %T %z", &tm);

    sircc_chan_log_info(chan, "topic of chan %s set by %s on %s",
                        chan_name, nickname, date);
}

SIRCC_MSG_HANDLER(rpl_namreply) {
    const char *chan_name, *users_str;
    struct sircc_chan *chan;
    const char *ptr;

    if (msg->nb_params < 4) {
        sircc_server_log_error(server, "missing arguments in RPL_NAMREPLY");
        return;
    }

    chan_name = msg->params[2];
    users_str = msg->params[3];

    chan = sircc_server_get_chan(server, chan_name);
    if (!chan) {
        sircc_server_log_error(server, "unknown chan '%s' in RPL_NAMREPLY",
                               chan_name);
        return;
    }

    sircc_chan_log_info(chan, "users on %s: %s",
                        chan_name, users_str);

    ptr = users_str;
    while (*ptr) {
        const char *space;
        size_t toklen;

        if (*ptr == '@' || *ptr == '+')
            ptr++;

        space = strchr(ptr, ' ');
        if (space) {
            toklen = (size_t)(space - ptr);
        } else {
            toklen = strlen(ptr);
        }

        if (toklen == 0)
            break;

        sircc_chan_add_user(chan, ptr, toklen);

        if (!space)
            break;
        ptr = space + 1;
    }
}

SIRCC_MSG_HANDLER(err_invalidcapcmd) {
    const char *cmdname, *errstr;

    /* IRCv3 Client Capability Negotiation 3.1
     *
     * If a client sends a subcommand which is not in the list above or
     * otherwise issues an invalid command, then numeric 410
     * (ERR_INVALIDCAPCMD) should be sent. The first parameter after the
     * client identifier (usually nickname) should be the commandname; the
     * second parameter should be a human-readable description of the error.
     */

    cmdname = NULL;
    errstr = NULL;

    if (msg->nb_params >= 2)
        cmdname = msg->params[1];

    if (msg->nb_params >= 3)
        errstr = msg->params[2];

    if (cmdname && errstr) {
        sircc_chan_log_error(NULL, "unknown cap command '%s': %s",
                             cmdname, errstr);
    } else if (cmdname) {
        sircc_chan_log_error(NULL, "unknown cap command '%s'",
                             cmdname);
    } else {
        sircc_chan_log_error(NULL, "unknown cap command");
    }
}

SIRCC_MSG_HANDLER(err_nosuchnick) {
    struct sircc_chan *chan;
    const char *nick;

    if (msg->nb_params < 3) {
        sircc_server_log_error(server, "missing arguments in ERR_NOSUCHNICK");
        return;
    }

    nick = msg->params[1];

    chan = sircc_server_get_chan(server, nick);
    if (chan) {
        sircc_server_remove_chan(server, chan);
        sircc_chan_delete(chan);
    }

    /* This error is also received for unknown channels */

    sircc_chan_log_error(NULL, "unknown nick/chan '%s'", nick);
}

SIRCC_MSG_HANDLER(err_notregistered) {
    sircc_chan_log_error(NULL, "you have not registered");
}

SIRCC_MSG_HANDLER(err_passwdmismatch) {
    const char *text;

    /* This can either mean that a password was required and not provided, or
     * that the provided password is incorrect. */

    text = msg->params[1];
    sircc_chan_log_error(NULL, "cannot register: %s", text);
}

SIRCC_MSG_HANDLER(err_unknownmode) {
    sircc_chan_log_error(NULL, "unknown mode flag");
}

SIRCC_MSG_HANDLER(err_noprivileges) {
    sircc_chan_log_error(NULL, "you are not irc operator");
}

SIRCC_MSG_HANDLER(err_chanoprivsneeded) {
    sircc_chan_log_error(NULL, "you are not chan operator");
}

SIRCC_MSG_HANDLER(err_umodeunknownflag) {
    sircc_chan_log_error(NULL, "unknown user mode flag");
}
