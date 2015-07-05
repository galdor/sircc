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

#ifdef SIRCC_PLATFORM_FREEBSD
#   include <sys/signal.h> /* Required for SIGWINCH */
#endif

#include "sircc.h"

static void sircc_usage(const char *, int);
static void sircc_version(void);

static void sircc_initialize(void);
static void sircc_shutdown(void);

static void sircc_load_servers(void);

static void sircc_on_signal(int, void *);
static void sircc_on_stdin_event(int, uint32_t, void *);

static void sircc_server_on_tcp_event(struct io_tcp_client *,
                                      enum io_tcp_client_event, void *);

static int sircc_cmp_users(const void *, const void *);


static struct c_memory_allocator sircc_memory_allocator = {
    .malloc = c_malloc,
    .calloc = c_calloc,
    .realloc = c_realloc,
    .free = c_free
};

struct sircc sircc;

int
main(int argc, char **argv) {
    const char *home;
    char cfgdir_default[PATH_MAX];

    const char *cfgdir;
    int opt;

    sircc_debug_initialize();

    setlocale(LC_ALL, "");

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    c_set_memory_allocator(&sircc_memory_allocator);

    home = getenv("HOME");
    if (!home)
        die("HOME environment variable not set");
    snprintf(cfgdir_default, sizeof(cfgdir_default), "%s/.sircc", home);
    cfgdir = cfgdir_default;

    opterr = 0;
    while ((opt = getopt(argc, argv, "c:hv")) != -1) {
        switch (opt) {
        case 'c':
            cfgdir = optarg;
            break;

        case 'h':
            sircc_usage(argv[0], 0);
            break;

        case 'v':
            sircc_version();
            break;

        case '?':
            sircc_usage(argv[0], 1);
        }
    }

    if (sircc_cfg_initialize(cfgdir) == -1)
        die("%s", c_get_error());

    if (sircc_processing_initialize() == -1)
        die("%s", c_get_error());

    sircc_load_servers();
    sircc_ui_initialize();
    sircc_initialize();

#ifdef SIRCC_WITH_X11
    sircc_x11_initialize();
#endif

    while (!sircc.do_exit) {
        if (io_base_read_events(sircc.io_base) == -1)
            die("cannot read events: %s", c_get_error());
    }

#ifdef SIRCC_WITH_X11
    sircc_x11_shutdown();
#endif

    sircc_shutdown();
    sircc_ui_shutdown();

    sircc_processing_shutdown();
    sircc_cfg_shutdown();

    EVP_cleanup();

    sircc_debug_shutdown();
    return 0;
}

static void
sircc_usage(const char *argv0, int exit_code) {
    printf("Usage: %s [-chv]\n"
            "\n"
            "Options:\n"
            "  -c <dir>  load the configuration from <dir> instead of ~/.sircc/\n"
            "  -h        display help\n"
            "  -v        display version information\n",
            argv0);
    exit(exit_code);
}

static void
sircc_version() {
    printf("sircc-" SIRCC_VERSION " " SIRCC_BUILD_ID "\n");
    exit(0);
}

void
die(const char *fmt, ...) {
    va_list ap;

    if (sircc.ui_setup)
        sircc_ui_shutdown();

    fprintf(stderr, "fatal error: ");

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    putc('\n', stderr);
    exit(1);
}

struct sircc_chan *
sircc_chan_new(struct sircc_server *server, const char *name) {
    struct sircc_chan *chan;

    assert(strlen(name) > 0);

    chan = c_malloc(sizeof(struct sircc_chan));
    memset(chan, 0, sizeof(struct sircc_chan));

    chan->name = c_strdup(name);
    chan->server = server;

    sircc_history_init(&chan->history, 1024);
    chan->history.max_nickname_length = server->max_nickname_length;

    if (!sircc_irc_is_chan_prefix(name[0]))
        chan->is_user = true;

    return chan;
}

void
sircc_chan_delete(struct sircc_chan *chan) {
    if (!chan)
        return;

    sircc_history_free(&chan->history);
    c_free(chan->name);
    c_free(chan->topic);

    for (size_t i = 0; i < chan->nb_users; i++)
        c_free(chan->users[i]);
    c_free(chan->users);

    c_free(chan);
}

void
sircc_chan_set_topic(struct sircc_chan *chan, const char *topic) {
    if (chan->topic) {
        c_free(chan->topic);
        chan->topic = NULL;
    }

    if (topic)
        chan->topic = c_strdup(topic);

    if (sircc_chan_is_current(chan)) {
        sircc_ui_topic_redraw();
        sircc_ui_update();
    }
}

struct sircc_history *
sircc_chan_history(struct sircc_chan *chan) {
    if (chan) {
        return &chan->history;
    } else {
        struct sircc_server *server;

        server = sircc_server_get_current();
        chan = server->current_chan;

        return chan ? &chan->history : &server->history;
    }
}

bool
sircc_chan_needs_redraw(struct sircc_chan *chan) {
    if (chan) {
        return sircc_chan_is_current(chan);
    } else {
        struct sircc_server *server;

        server = sircc_server_get_current();
        chan = server->current_chan;

        if (chan) {
            return sircc_chan_is_current(chan);
        } else {
            return sircc_server_is_current(server);
        }
    }
}

void
sircc_chan_on_msg_added(struct sircc_chan *chan, bool set_activity) {
    bool redraw_main, redraw_chans;

    redraw_main = sircc_chan_needs_redraw(chan);
    redraw_chans = false;

    if (set_activity) {
        if (chan && !sircc_chan_is_current(chan))
            chan->activity = true;
        redraw_chans = true;
    }

    if (redraw_main)
        sircc_ui_main_redraw();

    if (redraw_chans)
        sircc_ui_chans_redraw();

    if (redraw_main || redraw_chans)
        sircc_ui_update();
}

void
sircc_chan_log_info(struct sircc_chan *chan, const char *fmt, ...) {
    struct sircc_history *history;
    va_list ap;
    char *str;

    va_start(ap, fmt);
    c_vasprintf(&str, fmt, ap);
    va_end(ap);

    history = sircc_chan_history(chan);
    sircc_history_add_info(history, str);

    sircc_chan_on_msg_added(chan, false);
}

void
sircc_chan_log_error(struct sircc_chan *chan, const char *fmt, ...) {
    struct sircc_history *history;
    va_list ap;
    char *str;

    va_start(ap, fmt);
    c_vasprintf(&str, fmt, ap);
    va_end(ap);

    history = sircc_chan_history(chan);
    sircc_history_add_error(history, str);

    sircc_chan_on_msg_added(chan, false);
}

void
sircc_chan_add_msg(struct sircc_chan *chan, time_t date, const char *src,
                   const char *text) {
    struct sircc_history *history;

    history = sircc_chan_history(chan);
    sircc_history_add_chan_msg(history, date, c_strdup(src),
                               c_strdup(text));

    sircc_chan_on_msg_added(chan, true);
}

void
sircc_chan_add_server_msg(struct sircc_chan *chan, time_t date,
                          const char *src, const char *text) {
    struct sircc_history *history;

    history = sircc_chan_history(chan);
    sircc_history_add_server_msg(history, date, c_strdup(src),
                                 c_strdup(text));

    sircc_chan_on_msg_added(chan, true);
}

void
sircc_chan_add_action(struct sircc_chan *chan, time_t date, const char *src,
                      const char *text) {
    struct sircc_history *history;

    history = sircc_chan_history(chan);
    sircc_history_add_action(history, date, c_strdup(src),
                             c_strdup(text));

    sircc_chan_on_msg_added(chan, true);
}

void
sircc_chan_add_user(struct sircc_chan *chan, const char *user, size_t sz) {
    if (sz == (size_t)-1)
        sz = strlen(user);

    for (size_t i = 0; i < chan->nb_users; i++) {
        if (memcmp(chan->users[i], user, sz) == 0)
            return;
    }

    if (!chan->users) {
        chan->nb_users = 0;
        chan->users = c_malloc(sizeof(char *));
    } else {
        chan->users = c_realloc(chan->users,
                                    (chan->nb_users + 1) * sizeof(char *));
    }

    chan->users[chan->nb_users] = c_strndup(user, sz);
    chan->nb_users++;

    chan->users_sorted = false;
}

void
sircc_chan_remove_user(struct sircc_chan *chan, const char *user) {
    for (size_t i = 0; i < chan->nb_users; i++) {
        if (strcmp(chan->users[i], user) == 0) {
            c_free(chan->users[i]);

            if (i < chan->nb_users - 1) {
                memmove(chan->users + i, chan->users + i + 1,
                        (chan->nb_users - i - 1) * sizeof(char *));
            }

            chan->nb_users--;
            if (chan->nb_users == 0) {
                c_free(chan->users);
                chan->users = NULL;
            } else {
                chan->users = c_realloc(chan->users,
                                            chan->nb_users * sizeof(char *));
            }
            break;
        }
    }

    chan->users_sorted = false;
}

void
sircc_chan_sort_users(struct sircc_chan *chan) {
    qsort(chan->users, chan->nb_users, sizeof(char *), sircc_cmp_users);

    chan->users_sorted = true;
}

char *
sircc_chan_next_user_completion(struct sircc_chan *chan,
                                const char *prefix,
                                const char *last_completion) {
    const char *first_match;
    size_t prefix_len;

    prefix_len = strlen(prefix);

    first_match = NULL;

    for (size_t i = 0; i < chan->nb_users; i++) {
        const char *user;

        user = chan->users[i];

        if (strlen(user) >= prefix_len
            && memcmp(user, prefix, prefix_len) == 0) {
            if (!first_match)
                first_match = user;

            if (!last_completion || strcmp(user, last_completion) == 0) {
                const char *next_completion;
                const char *next_user;

                if (i < chan->nb_users - 1)
                    next_user = chan->users[i + 1];

                if (i < chan->nb_users - 1
                    && strlen(next_user) >= prefix_len
                    && memcmp(next_user, prefix, prefix_len) == 0) {
                    next_completion = next_user;
                } else {
                    next_completion = first_match;
                }

                return c_strdup(next_completion);
            }
        }
    }

    return NULL;
}

struct sircc_server *
sircc_server_new(const char *name) {
    struct sircc_server *server;

    server = c_malloc(sizeof(struct sircc_server));
    memset(server, 0, sizeof(struct sircc_server));

    server->name = name;

    server->max_nickname_length = 15;

    sircc_history_init(&server->history, 1024);
    server->history.max_nickname_length = server->max_nickname_length;

    return server;
}

void
sircc_server_delete(struct sircc_server *server) {
    struct sircc_chan *chan;

    if (!server)
        return;

    c_free(server->current_nickname);

    sircc_history_free(&server->history);

    chan = server->chans;
    while (chan) {
        struct sircc_chan *next;

        next = chan->next;
        sircc_chan_delete(chan);

        chan = next;
    }

    io_tcp_client_delete(server->tcp_client);

    c_free(server);
}

int
sircc_server_connect(struct sircc_server *server) {
    return io_tcp_client_connect(server->tcp_client,
                                 server->host, server->port);
}


void
sircc_server_disconnect(struct sircc_server *server) {
    io_tcp_client_disconnect(server->tcp_client);
}

void
sircc_server_trace(struct sircc_server *server, const char *fmt, ...) {
    struct c_buffer *buf;
    va_list ap;

    if (!server)
        server = sircc_server_get_current();

    buf = c_buffer_new();

    va_start(ap, fmt);
    c_buffer_add_vprintf(buf, fmt, ap);
    va_end(ap);

    sircc_history_add_trace(&server->history, c_buffer_dup_string(buf));
    c_buffer_delete(buf);

    if (server == sircc_server_get_current()) {
        sircc_ui_main_redraw();
        sircc_ui_update();
    }
}

void
sircc_server_log_info(struct sircc_server *server, const char *fmt, ...) {
    struct c_buffer *buf;
    va_list ap;

    if (!server)
        server = sircc_server_get_current();

    buf = c_buffer_new();

    va_start(ap, fmt);
    c_buffer_add_vprintf(buf, fmt, ap);
    va_end(ap);

    sircc_history_add_info(&server->history, c_buffer_dup_string(buf));
    c_buffer_delete(buf);

    if (server == sircc_server_get_current()) {
        sircc_ui_main_redraw();
        sircc_ui_update();
    }
}

void
sircc_server_log_error(struct sircc_server *server, const char *fmt, ...) {
    struct c_buffer *buf;
    va_list ap;

    if (!server)
        server = sircc_server_get_current();

    buf = c_buffer_new();

    va_start(ap, fmt);
    c_buffer_add_vprintf(buf, fmt, ap);
    va_end(ap);

    sircc_history_add_error(&server->history, c_buffer_dup_string(buf));
    c_buffer_delete(buf);

    if (server == sircc_server_get_current()) {
        sircc_ui_main_redraw();
        sircc_ui_update();
    }
}

void
sircc_server_add_server_msg(struct sircc_server *server, time_t date,
                            const char *src, const char *msg) {
    if (!server)
        server = sircc_server_get_current();

    sircc_history_add_server_msg(&server->history, date, c_strdup(src),
                                 c_strdup(msg));

    if (server == sircc_server_get_current()) {
        sircc_ui_main_redraw();
        sircc_ui_update();
    }
}

void
sircc_server_write(struct sircc_server *server, const char *buf, size_t sz) {
    io_tcp_client_write(server->tcp_client, buf, sz);
}

void
sircc_server_vprintf(struct sircc_server *server, const char *fmt, va_list ap) {
    char *string;
    int sz;

    sz = c_vasprintf(&string, fmt, ap);

    io_tcp_client_write(server->tcp_client, string, (size_t)sz);

    c_free(string);
}

void
sircc_server_printf(struct sircc_server *server, const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    sircc_server_vprintf(server, fmt, ap);
    va_end(ap);
}

void
sircc_server_on_connection_established(struct sircc_server *server) {
    sircc_server_log_info(server, "connected to %s:%u",
                          server->host, server->port);

    sircc_server_printf(server, "CAP LS\r\n");
    if (server->password)
        sircc_server_printf(server, "PASS %s\r\n", server->password);
    sircc_server_printf(server, "NICK %s\r\n", server->nickname);
    sircc_server_printf(server, "USER %s 0 * :%s\r\n",
                        server->nickname, server->realname);
}

void
sircc_server_read_msgs(struct sircc_server *server) {
    struct c_buffer *rbuf;

    rbuf = io_tcp_client_rbuf(server->tcp_client);

    while (c_buffer_length(rbuf) > 0) {
        struct sircc_msg msg;
        int ret;

        {
            const char *ptr;
            char *cr;

            ptr = c_buffer_data(rbuf);

            cr = strchr(ptr, '\r');
            if (cr) {
                *cr = '\0';
                sircc_server_trace(server, "%s", ptr);
                *cr = '\r';
            }
        }

        ret = sircc_msg_parse(&msg, rbuf);
        if (ret == -1) {
            sircc_server_log_error(server, "cannot parse message: %s",
                                   c_get_error());
            sircc_server_disconnect(server);
            return;
        }

        if (ret == 0)
            break;

        c_buffer_skip(rbuf, (size_t)ret);

        sircc_server_msg_process(server, &msg);
        sircc_msg_free(&msg);
    }
}

void
sircc_server_msg_process(struct sircc_server *server, struct sircc_msg *msg) {
    sircc_call_msg_handler(server, msg);
}

struct sircc_chan *
sircc_server_get_chan(struct sircc_server *server, const char *name) {
    struct sircc_chan *chan;

    chan = server->chans;
    while (chan) {
        if (strcmp(chan->name, name) == 0)
            return chan;

        chan = chan->next;
    }

    return NULL;
}

bool
sircc_chan_is_current(struct sircc_chan *chan) {
    return sircc_server_is_current(chan->server)
        && chan->server->current_chan == chan;
}

void
sircc_server_add_chan(struct sircc_server *server, struct sircc_chan *chan) {
    struct sircc_chan *last;

    last = server->chans;
    while (last && last->next)
        last = last->next;

    if (!last)
        server->chans = chan;
    if (last)
        last->next = chan;
    chan->prev = last;
    chan->next = NULL;

    sircc_ui_chans_redraw();
    sircc_ui_update();
}

void
sircc_server_remove_chan(struct sircc_server *server,
                         struct sircc_chan *chan) {
    struct sircc_chan *selected_chan;

    selected_chan = server->last_chan ? server->last_chan : chan->prev;

    if (chan->prev)
        chan->prev->next = chan->next;
    if (chan->next)
        chan->next->prev = chan->prev;

    if (server->chans == chan)
        server->chans = chan->next;

    if (server->current_chan == chan)
        sircc_ui_server_select_chan(server, selected_chan);

    server->last_chan = NULL;

    sircc_ui_chans_redraw();
    sircc_ui_update();
}

struct sircc_server *
sircc_server_get_current(void) {
    if (sircc.current_server != -1) {
        return c_ptr_vector_entry(sircc.servers, (size_t)sircc.current_server);
    } else {
        return NULL;
    }
}

bool
sircc_server_is_current(struct sircc_server *server) {
    return sircc_server_get_current() == server;
}

void
sircc_server_send_privmsg(struct sircc_server *server, const char *target,
                          const char *text) {
    sircc_server_printf(server, "PRIVMSG %s :%s\r\n",
                        target, text);
}

static void
sircc_initialize(void) {
    sircc.io_base = io_base_new();

#define SIRCC_WATCH_SIGNAL(signo_)                                \
    if (io_base_watch_signal(sircc.io_base, signo_,               \
                             sircc_on_signal, NULL) == -1) {      \
        die("cannot watch signal %d: %s", signo_, c_get_error()); \
    }

    SIRCC_WATCH_SIGNAL(SIGINT);
    SIRCC_WATCH_SIGNAL(SIGTERM);
    SIRCC_WATCH_SIGNAL(SIGWINCH);
#undef SIRCC_WATCH_SIGNAL

    if (io_base_watch_fd(sircc.io_base, STDIN_FILENO, IO_EVENT_FD_READ,
                         sircc_on_stdin_event, NULL) == -1) {
        die("cannot watch stdin: %s", c_get_error());
    }

    sircc.msg_handlers = c_hash_table_new(c_hash_string, c_equal_string);
    sircc_init_msg_handlers();

    sircc.input_buf = c_buffer_new();
    sircc.input_read_buf = c_buffer_new();
    sircc.prompt_buf = c_buffer_new();

    for (size_t i = 0; i < c_ptr_vector_length(sircc.servers); i++) {
        struct sircc_server *server;
        struct io_ssl_cfg ssl_cfg;

        server = c_ptr_vector_entry(sircc.servers, i);

        server->tcp_client = io_tcp_client_new(sircc.io_base,
                                               sircc_server_on_tcp_event,
                                               server);

        if (server->use_ssl) {
            char ca_cert[PATH_MAX];

            memset(&ssl_cfg, 0, sizeof(struct io_ssl_cfg));

            sircc_cfg_ssl_file_path(ca_cert, server->ssl_ca_cert, PATH_MAX);
            ssl_cfg.ca_cert_path = ca_cert;

            if (io_tcp_client_enable_ssl(server->tcp_client, &ssl_cfg) == -1)
                die("cannot enable ssl: %s", c_get_error());
        }

        if (server->autoconnect)
            sircc_server_connect(server);
    }
}

static void
sircc_shutdown(void) {
    for (size_t i = 0; i < c_ptr_vector_length(sircc.servers); i++) {
        struct sircc_server *server;

        server = c_ptr_vector_entry(sircc.servers, i);

        sircc_server_disconnect(server);
        sircc_server_delete(server);
    }
    c_ptr_vector_delete(sircc.servers);

    c_hash_table_delete(sircc.msg_handlers);

    c_buffer_delete(sircc.input_read_buf);
    c_buffer_delete(sircc.input_buf);
    c_buffer_delete(sircc.prompt_buf);

    io_base_unwatch_signal(sircc.io_base, SIGINT);
    io_base_unwatch_signal(sircc.io_base, SIGTERM);
    io_base_unwatch_signal(sircc.io_base, SIGWINCH);

    io_base_delete(sircc.io_base);
}

static void
sircc_load_servers(void) {
    sircc.servers = c_ptr_vector_new();

    for (size_t i = 0; i < sircc.cfg.nb_servers; i++) {
        struct sircc_server *server;

        server = sircc_server_new(sircc.cfg.servers[i]);

        server->autoconnect = sircc_cfg_server_boolean(server, "autoconnect",
                                                       true);

        server->host = sircc_cfg_server_string(server, "host", NULL);
        server->port = sircc_cfg_server_integer(server, "port", 6667);

        server->use_ssl = sircc_cfg_server_boolean(server, "ssl", false);

        if (server->use_ssl) {
            server->ssl_ca_cert = sircc_cfg_server_string(server,
                                                          "ssl_ca_certificate",
                                                          NULL);
            if (!server->ssl_ca_cert)
                die("missing ssl_ca_certificate for server %s", server->name);
        }

        server->nickname = sircc_cfg_server_string(server, "nickname", NULL);
        server->realname = sircc_cfg_server_string(server, "realname",
                                                   server->nickname);
        server->password = sircc_cfg_server_string(server, "password",
                                                   server->password);

        server->max_nickname_length =
            sircc_cfg_server_integer(server, "max_nickname_length", 15);
        if (server->max_nickname_length <= 0)
            die("invalid nickname length: %d", server->max_nickname_length);
        server->history.max_nickname_length = server->max_nickname_length;

        if (!server->host)
            die("no host defined for server %s", server->name);

        if (!server->nickname)
            die("no nickname defined for server %s", server->name);

        server->current_nickname = c_strdup(server->nickname);

        c_ptr_vector_append(sircc.servers, server);
    }

    if (c_ptr_vector_length(sircc.servers) == 0)
        die("no server defined in configuration");
}

static void
sircc_on_signal(int signo, void *arg) {
    switch (signo) {
    case SIGINT:
    case SIGTERM:
        sircc.do_exit = true;
        break;

    case SIGWINCH:
        sircc_ui_on_resize();
        break;
    }
}

static void
sircc_on_stdin_event(int fd, uint32_t events, void *arg) {
    static bool escape = false;

    struct sircc_server *server;
    ssize_t ret;
    unsigned char *ptr;
    size_t len;

    server = sircc_server_get_current();

    ret = c_buffer_read(sircc.input_read_buf, STDIN_FILENO, 64);
    if (ret < 0)
        die("cannot read terminal device: %s", strerror(errno));
    if (ret == 0)
        die("eof on terminal device");

    len = c_buffer_length(sircc.input_read_buf);
    ptr = (unsigned char *)c_buffer_data(sircc.input_read_buf);

    for (size_t i = 0; i < len; i++) {
        unsigned char c;

        c = ptr[i];

        if (c == 1) {
            /* ^A */
            sircc_ui_prompt_move_cursor_beginning();
        } else if (c == 2) {
            /* ^B */
            sircc_ui_prompt_move_cursor_backward();
        } else if (c == 5) {
            /* ^E */
            sircc_ui_prompt_move_cursor_end();
        } else if (c == 6) {
            /* ^F */
            sircc_ui_prompt_move_cursor_forward();
        } else if (c == 8) {
            /* Backspace */
            sircc_ui_prompt_delete_previous_char();
        } else if (c == 9) {
            /* Tabulation */
            sircc_ui_completion_next();
        } else if (c == 11) {
            /* ^K */
            sircc_ui_prompt_delete_from_cursor();
        } else if (c == 12) {
            /* ^L */
            sircc_ui_on_resize();
        } else if (c == 13) {
            /* Return */
            sircc_ui_prompt_execute();
            sircc_ui_prompt_clear();
        } else if (c == 14) {
            /* ^N */
            sircc_ui_server_select_next_chan(server);
        } else if (c == 16) {
            /* ^P */
            sircc_ui_server_select_previous_chan(server);
        } else if (c == 25) {
            /* ^Y */
            sircc_ui_prompt_add_selection();
        } else if (c == 27) {
            /* Escape */
            escape = true;
        } else if (escape) {
            if (c == 'p') {
                sircc_ui_server_select_previous();
            } else if (c == 'n') {
                sircc_ui_server_select_next();
            }

            escape = false;
        } else {
            c_buffer_add(sircc.input_buf, (char *)&c, 1);
        }
    }

    {
        char *utf8_str;
        size_t nb_bytes;

        utf8_str = sircc_str_locale_to_utf8(c_buffer_data(sircc.input_buf),
                                            c_buffer_length(sircc.input_buf),
                                            &nb_bytes);
        if (!utf8_str) {
            sircc_chan_log_error(NULL, "cannot convert input to UTF-8: %s",
                                 c_get_error());

            c_buffer_clear(sircc.input_read_buf);
            c_buffer_clear(sircc.input_buf);
        }

        sircc_ui_prompt_add(utf8_str);
        c_free(utf8_str);

        /* If there is a truncated multibyte character at the end of
         * input_buf, it will stay in it to be completed the next time there
         * is something to read on stdin. */
        c_buffer_skip(sircc.input_buf, nb_bytes);
    }

    c_buffer_clear(sircc.input_read_buf);
}

static void
sircc_server_on_tcp_event(struct io_tcp_client *client,
                          enum io_tcp_client_event event, void *arg) {
    struct sircc_server *server;

    server = arg;

    switch (event) {
    case IO_TCP_CLIENT_EVENT_CONN_ESTABLISHED:
        sircc_server_log_info(server, "connection established");
        sircc_server_on_connection_established(server);
        break;

    case IO_TCP_CLIENT_EVENT_CONN_FAILED:
        sircc_server_log_error(server, "connection failed");
        break;

    case IO_TCP_CLIENT_EVENT_CONN_CLOSED:
        sircc_server_log_info(server, "connection closed");
        break;

    case IO_TCP_CLIENT_EVENT_ERROR:
        sircc_server_log_error(server, "%s", c_get_error());
        break;

    case IO_TCP_CLIENT_EVENT_DATA_READ:
        sircc_server_read_msgs(server);
        break;
    }
}

static int
sircc_cmp_users(const void *p1, const void *p2) {
    const char **u1, **u2;

    u1 = (const char **)p1;
    u2 = (const char **)p2;

    return strcmp(*u1, *u2);
}
