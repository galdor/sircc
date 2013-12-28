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

#include <assert.h>
#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#ifdef SIRCC_PLATFORM_FREEBSD
#   include <sys/signal.h> /* Required for SIGWINCH */
#endif

#include "sircc.h"

typedef void (*sircc_msg_handler)(struct sircc_server *, struct sircc_msg *);


static void usage(const char *, int);

static void sircc_signal_handler(int);

static void sircc_initialize(void);
static void sircc_shutdown(void);
static void sircc_server_add(struct sircc_server *);
static void sircc_setup_poll_array(void);
static void sircc_poll(void);
static void sircc_read_signal(void);
static void sircc_read_input(void);
static void sircc_set_msg_handler(const char *, sircc_msg_handler);

static void sircc_on_msg_join(struct sircc_server *, struct sircc_msg *);
static void sircc_on_msg_part(struct sircc_server *, struct sircc_msg *);
static void sircc_on_msg_ping(struct sircc_server *, struct sircc_msg *);
static void sircc_on_msg_privmsg(struct sircc_server *, struct sircc_msg *);
static void sircc_on_msg_topic(struct sircc_server *, struct sircc_msg *);
static void sircc_on_msg_rpl_welcome(struct sircc_server *, struct sircc_msg *);
static void sircc_on_msg_rpl_notopic(struct sircc_server *, struct sircc_msg *);
static void sircc_on_msg_rpl_topic(struct sircc_server *, struct sircc_msg *);


static struct ht_memory_allocator sircc_ht_allocator = {
    .malloc = sircc_malloc,
    .calloc = sircc_calloc,
    .realloc = sircc_realloc,
    .free = sircc_free
};

__thread char sircc_error_buf[SIRCC_ERROR_BUFSZ];

struct sircc sircc;

int
main(int argc, char **argv) {
    struct sircc_server *server;
    int opt, nb_args;

    setlocale(LC_ALL, "");

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ht_set_memory_allocator(&sircc_ht_allocator);

    opterr = 0;
    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            usage(argv[0], 0);
            break;

        case '?':
            usage(argv[0], 1);
        }
    }

    nb_args = argc - optind;

    server = sircc_server_new();
    server->host = "localhost";
    server->port = "6667";
    server->nickname = "sircc";
    server->realname = "Simple IRC Client";
    sircc_server_add(server);

    server = sircc_server_new();
    server->host = "127.0.0.1";
    server->port = "6667";
    server->nickname = "sircc2";
    server->realname = "Simple IRC Client";
    sircc_server_add(server);
#endif

    server = sircc_server_new();
    server->host = "galdor.org";
    server->port = "6668";
    server->use_ssl = true;
    server->nickname = "sircc3";
    server->realname = "Simple IRC Client";
    sircc_server_add(server);

    sircc_ui_initialize();
    sircc_initialize();

    sircc_set_msg_handler("JOIN", sircc_on_msg_join);
    sircc_set_msg_handler("PART", sircc_on_msg_part);
    sircc_set_msg_handler("PING", sircc_on_msg_ping);
    sircc_set_msg_handler("PRIVMSG", sircc_on_msg_privmsg);
    sircc_set_msg_handler("TOPIC", sircc_on_msg_topic);
    sircc_set_msg_handler("001", sircc_on_msg_rpl_welcome);
    sircc_set_msg_handler("331", sircc_on_msg_rpl_notopic);
    sircc_set_msg_handler("332", sircc_on_msg_rpl_topic);

    while (!sircc.do_exit) {
        sircc_poll();
    }

    sircc_shutdown();
    sircc_ui_shutdown();

    EVP_cleanup();
    return 0;
}

static void
usage(const char *argv0, int exit_code) {
    printf("Usage: %s [-h]\n"
            "\n"
            "Options:\n"
            "  -h         display help\n",
            argv0);
    exit(exit_code);
}

static void
sircc_signal_handler(int signo) {
    ssize_t ret;

    ret = write(sircc.signal_pipe[1], &signo, sizeof(signo));
    if (ret < (ssize_t)sizeof(signo))
        die("cannot write to pipe: %m");
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

const char *
sircc_get_error() {
    return sircc_error_buf;
}

void
sircc_set_error(const char *fmt, ...) {
    char buf[SIRCC_ERROR_BUFSZ];
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = vsnprintf(buf, SIRCC_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    if ((size_t)ret >= SIRCC_ERROR_BUFSZ) {
        memcpy(sircc_error_buf, buf, SIRCC_ERROR_BUFSZ);
        sircc_error_buf[SIRCC_ERROR_BUFSZ - 1] = '\0';
        return;
    }

    strncpy(sircc_error_buf, buf, (size_t)ret + 1);
    sircc_error_buf[ret] = '\0';
}

struct sircc_chan *
sircc_chan_new(struct sircc_server *server, const char *name) {
    struct sircc_chan *chan;

    chan = sircc_malloc(sizeof(struct sircc_chan));
    memset(chan, 0, sizeof(struct sircc_chan));

    chan->name = sircc_strdup(name);
    chan->server = server;

    sircc_history_init(&chan->history, 1024);

    return chan;
}

void
sircc_chan_delete(struct sircc_chan *chan) {
    if (!chan)
        return;

    sircc_history_free(&chan->history);
    sircc_free(chan->name);
    sircc_free(chan->topic);
    sircc_free(chan);
}

void
sircc_chan_set_topic(struct sircc_chan *chan, const char *topic) {
    if (chan->topic) {
        sircc_free(chan->topic);
        chan->topic = NULL;
    }

    if (topic)
        chan->topic = sircc_strdup(topic);

    if (sircc_chan_is_current(chan)) {
        sircc_ui_topic_redraw();
        sircc_ui_update();
    }
}

void
sircc_chan_log_info(struct sircc_chan *chan, const char *fmt, ...) {
    struct sircc_buf buf;
    va_list ap;

    if (!chan) {
        struct sircc_server *server;

        server = sircc_server_get_current();
        chan = server->current_chan;
        if (!chan)
            return;
    }

    sircc_buf_init(&buf);

    va_start(ap, fmt);
    sircc_buf_add_vprintf(&buf, fmt, ap);
    va_end(ap);

    sircc_history_add_info(&chan->history, sircc_buf_dup_str(&buf));
    sircc_buf_free(&buf);

    if (sircc_chan_is_current(chan)) {
        sircc_ui_main_redraw();
        sircc_ui_update();
    }
}

void
sircc_chan_log_msg(struct sircc_chan *chan, const char *src,
                   const char *fmt, ...) {
    struct sircc_buf buf;
    va_list ap;

    if (!chan) {
        struct sircc_server *server;

        server = sircc_server_get_current();
        chan = server->current_chan;
        if (!chan)
            return;
    }

    sircc_buf_init(&buf);

    va_start(ap, fmt);
    sircc_buf_add_vprintf(&buf, fmt, ap);
    va_end(ap);

    sircc_history_add_chan_msg(&chan->history, sircc_strdup(src),
                               sircc_buf_dup_str(&buf));
    sircc_buf_free(&buf);

    if (sircc_chan_is_current(chan)) {
        sircc_ui_main_redraw();
        sircc_ui_update();
    }
}

struct sircc_server *
sircc_server_new(void) {
    struct sircc_server *server;

    server = sircc_malloc(sizeof(struct sircc_server));
    memset(server, 0, sizeof(struct sircc_server));

    server->sock = -1;

    sircc_buf_init(&server->rbuf);
    sircc_buf_init(&server->wbuf);

    sircc_history_init(&server->history, 1024);

    server->state = SIRCC_SERVER_DISCONNECTED;

    return server;
}

void
sircc_server_delete(struct sircc_server *server) {
    struct sircc_chan *chan;

    if (!server)
        return;

    if (server->addresses) {
        freeaddrinfo(server->addresses[0]);
        sircc_free(server->addresses);
    }

    sircc_buf_free(&server->rbuf);
    sircc_buf_free(&server->wbuf);

    sircc_history_free(&server->history);

    chan = server->chans;
    while (chan) {
        struct sircc_chan *next;

        next = chan->next;
        sircc_chan_delete(chan);

        chan = next;
    }

    sircc_free(server);
}

int
sircc_server_prepare_connection(struct sircc_server *server) {
    assert(server->state == SIRCC_SERVER_DISCONNECTED);

    if (server->addresses) {
        sircc_free(server->addresses);
        server->addresses = NULL;
        server->nb_addresses = 0;
    }

    if (sircc_address_resolve(server->host, server->port,
                              &server->addresses,
                              &server->nb_addresses) == -1) {
        sircc_server_log_error(server, "%s", sircc_get_error());
        server->state = SIRCC_SERVER_BROKEN;
        return -1;
    }

    server->next_address_idx = 0;
    return 0;
}

int
sircc_server_connect(struct sircc_server *server) {
    struct addrinfo *ai;

    assert(server->state == SIRCC_SERVER_DISCONNECTED
        || server->state == SIRCC_SERVER_CONNECTING);

    ai = server->addresses[server->next_address_idx];

    if (server->state == SIRCC_SERVER_DISCONNECTED) {
        server->sock = sircc_socket_open(ai);
        if (server->sock == -1) {
            sircc_server_log_error(server, "%s", sircc_get_error());
            return -1;
        }

        server->pollfd->fd = server->sock;
        server->state = SIRCC_SERVER_CONNECTING;
    }

    sircc_server_trace(server, "connecting to %s:%s",
                       server->host, server->port);

    if (connect(server->sock, ai->ai_addr, ai->ai_addrlen) == -1) {
        if (errno == EINPROGRESS) {
            server->pollfd->events = POLLOUT;
            return 0;
        } else {
            /* We will try another address next time */
            sircc_server_log_error(server, "cannot connect to %s:%s: %m",
                                   server->host, server->port);
            server->next_address_idx++;
            if (server->next_address_idx >= server->nb_addresses)
                server->next_address_idx = 0;

            return -1;
        }
    }

    server->state = SIRCC_SERVER_CONNECTED;
    if (server->use_ssl) {
        if (sircc_server_ssl_connect(server) == -1)
            return -1;
    } else {
        sircc_server_on_connection_established(server);
    }

    return 0;
}

int
sircc_server_ssl_connect(struct sircc_server *server) {
    long options;
    int ret;

    assert(server->state == SIRCC_SERVER_CONNECTED
        || server->state == SIRCC_SERVER_SSL_CONNECTING);

    if (server->state == SIRCC_SERVER_CONNECTED) {
        server->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
        if (!server->ssl_ctx) {
            sircc_server_log_error(server, "cannot create ssl context: %s",
                                   sircc_ssl_get_error());
            goto error;
        }

        options = SSL_OP_ALL | SSL_OP_NO_SSLv2;
        SSL_CTX_set_options(server->ssl_ctx, options);

        options  = SSL_MODE_ENABLE_PARTIAL_WRITE;
        options |= SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
        SSL_CTX_set_mode(server->ssl_ctx, options);

        if (SSL_CTX_set_cipher_list(server->ssl_ctx, "HIGH") == 0) {
            sircc_server_log_error(server, "cannot set cipher list: %s",
                                   sircc_ssl_get_error());
            goto error;
        }

        server->ssl = SSL_new(server->ssl_ctx);
        if (!server->ssl) {
            sircc_server_log_error(server, "cannot create ssl structure: %s",
                                   sircc_ssl_get_error());
            goto error;
        }

        if (SSL_set_fd(server->ssl, server->sock) == 0) {
            sircc_server_log_error(server, "cannot set ssl file descriptor: %s",
                                   sircc_ssl_get_error());
            goto error;
        }

        server->state = SIRCC_SERVER_SSL_CONNECTING;
    }

    ret = SSL_connect(server->ssl);
    if (ret <= 0) {
        int err;

        err = SSL_get_error(server->ssl, ret);
        switch (err) {
        case SSL_ERROR_WANT_READ:
            server->pollfd->events = POLLIN;
            break;

        case SSL_ERROR_WANT_WRITE:
            server->pollfd->events = POLLOUT;
            break;

        case SSL_ERROR_WANT_CONNECT:
            break;

        default:
            sircc_server_log_error(server,
                                   "cannot establish ssl connection: %s",
                                   sircc_ssl_get_error());
            goto error;
        }

        return -1;
    }

    server->state = SIRCC_SERVER_SSL_CONNECTED;
    sircc_server_on_connection_established(server);
    return 0;

error:
    close(server->sock);
    server->sock = -1;

    server->state = SIRCC_SERVER_BROKEN;
    return -1;
}

void
sircc_server_disconnect(struct sircc_server *server) {
    if (server->sock > 0) {
        close(server->sock);
        server->sock = -1;
        server->pollfd->fd = -1;
    }

    sircc_buf_clear(&server->rbuf);
    sircc_buf_clear(&server->wbuf);

    if (server->ssl_ctx)
        SSL_CTX_free(server->ssl_ctx);
    if (server->ssl)
        SSL_free(server->ssl);

    server->state = SIRCC_SERVER_DISCONNECTED;
}

void
sircc_server_trace(struct sircc_server *server, const char *fmt, ...) {
    struct sircc_buf buf;
    va_list ap;

    if (!server)
        server = sircc_server_get_current();

    sircc_buf_init(&buf);

    va_start(ap, fmt);
    sircc_buf_add_vprintf(&buf, fmt, ap);
    va_end(ap);

    sircc_history_add_trace(&server->history, sircc_buf_dup_str(&buf));
    sircc_buf_free(&buf);

    if (server == sircc_server_get_current()) {
        sircc_ui_main_redraw();
        sircc_ui_update();
    }
}

void
sircc_server_log_info(struct sircc_server *server, const char *fmt, ...) {
    struct sircc_buf buf;
    va_list ap;

    if (!server)
        server = sircc_server_get_current();

    sircc_buf_init(&buf);

    va_start(ap, fmt);
    sircc_buf_add_vprintf(&buf, fmt, ap);
    va_end(ap);

    sircc_history_add_info(&server->history, sircc_buf_dup_str(&buf));
    sircc_buf_free(&buf);

    if (server == sircc_server_get_current()) {
        sircc_ui_main_redraw();
        sircc_ui_update();
    }
}

void
sircc_server_log_error(struct sircc_server *server, const char *fmt, ...) {
    struct sircc_buf buf;
    va_list ap;

    if (!server)
        server = sircc_server_get_current();

    sircc_buf_init(&buf);

    va_start(ap, fmt);
    sircc_buf_add_vprintf(&buf, fmt, ap);
    va_end(ap);

    sircc_history_add_error(&server->history, sircc_buf_dup_str(&buf));
    sircc_buf_free(&buf);

    if (server == sircc_server_get_current()) {
        sircc_ui_main_redraw();
        sircc_ui_update();
    }
}

void
sircc_server_write(struct sircc_server *server, const char *buf, size_t sz) {
    sircc_buf_add(&server->wbuf, buf, sz);

    server->pollfd->events |= POLLOUT;
}

int
sircc_server_vprintf(struct sircc_server *server, const char *fmt, va_list ap) {
    if (sircc_buf_add_vprintf(&server->wbuf, fmt, ap) == -1)
        return -1;

    server->pollfd->events |= POLLOUT;
    return 0;
}

int
sircc_server_printf(struct sircc_server *server, const char *fmt, ...) {
    va_list ap;
    int ret;

    ret = 0;

    va_start(ap, fmt);
    ret = sircc_server_vprintf(server, fmt, ap);
    va_end(ap);

    return ret;
}

void
sircc_server_on_pollin(struct sircc_server *server) {
    switch (server->state) {
    case SIRCC_SERVER_SSL_CONNECTING:
        sircc_server_ssl_connect(server);
        break;

    case SIRCC_SERVER_CONNECTED:
        {
            ssize_t ret;

            ret = sircc_buf_read(&server->rbuf, server->sock, BUFSIZ);
            if (ret == -1) {
                sircc_server_log_error(server, "cannot read socket: %m");
                sircc_server_disconnect(server);
                return;
            }

            if (ret == 0) {
                sircc_server_log_info(server, "connection closed");
                sircc_server_disconnect(server);
                return;
            }

            sircc_server_read_msgs(server);
        }
        break;

    case SIRCC_SERVER_SSL_CONNECTED:
        {
            int ret, err;
            char buf[BUFSIZ];

            ret = SSL_read(server->ssl, buf, sizeof(buf));
            if (ret <= 0) {
                err = SSL_get_error(server->ssl, ret);

                switch (err) {
                case SSL_ERROR_WANT_READ:
                    break;

                case SSL_ERROR_WANT_WRITE:
                    server->pollfd->events |= POLLOUT;
                    break;

                case SSL_ERROR_ZERO_RETURN:
                    sircc_server_log_info(server, "connection closed");
                    sircc_server_disconnect(server);
                    break;

                default:
                    sircc_server_log_error(server, "cannot read socket: %s",
                                           sircc_ssl_get_error());
                    sircc_server_disconnect(server);
                    break;
                }

                return;
            }

            sircc_buf_add(&server->rbuf, buf, (size_t)ret);
            sircc_server_read_msgs(server);
        }
        break;

    default:
        sircc_server_log_error(server, "ignoring pollin event in state %d",
                               server->state);
        break;
    }
}

void
sircc_server_on_pollout(struct sircc_server *server) {
    switch (server->state) {
    case SIRCC_SERVER_CONNECTING:
        {
            int err;

            if (sircc_socket_get_so_error(server->sock, &err) == -1) {
                sircc_server_log_error(server, "%s", sircc_get_error());
                sircc_server_disconnect(server);
                return;
            }

            if (err == 0) {
                server->state = SIRCC_SERVER_CONNECTED;
                if (server->use_ssl) {
                    sircc_server_ssl_connect(server);
                } else {
                    sircc_server_on_connection_established(server);
                }
            } else if (err == EINPROGRESS) {
                return;
            } else {
                sircc_server_log_error(server, "cannot connect to %s:%s: %s",
                                       server->host, server->port,
                                       strerror(err));
                sircc_server_disconnect(server);
            }
        }
        break;

    case SIRCC_SERVER_SSL_CONNECTING:
        sircc_server_ssl_connect(server);
        break;

    case SIRCC_SERVER_CONNECTED:
        {
            ssize_t ret;

            ret = sircc_buf_write(&server->wbuf, server->sock);
            if (ret == -1) {
                sircc_server_log_error(server, "cannot write to socket: %m");
                sircc_server_disconnect(server);
            }

            if (sircc_buf_length(&server->wbuf) == 0)
                server->pollfd->events &= ~POLLOUT;
        }
        break;

    case SIRCC_SERVER_SSL_CONNECTED:
        {
            const char *data;
            int len, ret, err;

            data = sircc_buf_data(&server->wbuf);

            if (server->ssl_last_write_length > 0) {
                len = server->ssl_last_write_length;
            } else {
                len = (int)sircc_buf_length(&server->wbuf);
            }

            ret = SSL_write(server->ssl, data, len);
            if (ret <= 0) {
                err = SSL_get_error(server->ssl, ret);

                switch (err) {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                    /* From SSL_write(3):
                     *
                     * When an SSL_write() operation has to be repeated
                     * because of SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE,
                     * it must be repeated with the same arguments.
                     *
                     * So we save the length we used to reuse it next time. */
                    server->ssl_last_write_length = len;
                    break;

                case SSL_ERROR_ZERO_RETURN:
                    sircc_server_log_info(server, "connection closed");
                    sircc_server_disconnect(server);
                    break;

                default:
                    sircc_server_log_error(server, "cannot write to socket: %s",
                                           sircc_ssl_get_error());
                    sircc_server_disconnect(server);
                    break;
                }

                return;
            }

            server->ssl_last_write_length = 0;

            sircc_buf_skip(&server->wbuf, (size_t)ret);
            if (sircc_buf_length(&server->wbuf) == 0)
                server->pollfd->events &= ~POLLOUT;
        }
        break;

    default:
        sircc_server_log_error(server, "ignoring pollout event in state %d",
                               server->state);
        break;
    }
}

void
sircc_server_on_connection_established(struct sircc_server *server) {
    assert(server->state == SIRCC_SERVER_CONNECTED
        || server->state == SIRCC_SERVER_SSL_CONNECTED);

    sircc_server_log_info(server, "connected to %s:%s",
                          server->host, server->port);

    server->pollfd->events = POLLIN;

    sircc_server_printf(server, "NICK %s\r\n",
                        server->nickname);
    sircc_server_printf(server, "USER %s 0 * :%s\r\n",
                        server->nickname, server->realname);
}

void
sircc_server_read_msgs(struct sircc_server *server) {
    while (sircc_buf_length(&server->rbuf) > 0) {
        struct sircc_msg msg;
        int ret;

        {
            const char *ptr;
            char *cr;

            ptr = sircc_buf_data(&server->rbuf);

            cr = strchr(ptr, '\r');
            if (cr) {
                *cr = '\0';
                sircc_server_trace(server, "%s", ptr);
                *cr = '\r';
            }
        }

        ret = sircc_msg_parse(&msg, &server->rbuf);
        if (ret == -1) {
            sircc_server_log_error(server, "cannot parse message: %s",
                                   sircc_get_error());
            sircc_server_disconnect(server);
            return;
        }

        if (ret == 0)
            break;

        sircc_buf_skip(&server->rbuf, (size_t)ret);

        sircc_server_msg_process(server, &msg);
        sircc_msg_free(&msg);
    }
}

void
sircc_server_msg_process(struct sircc_server *server, struct sircc_msg *msg) {
    sircc_msg_handler handler;

    if (ht_table_get(sircc.msg_handlers, msg->command,
                     (void **)&handler) == 0) {
        return;
    }

    handler(server, msg);
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
    if (chan->prev)
        chan->prev->next = chan->next;
    if (chan->next)
        chan->next->prev = chan->prev;

    if (server->chans == chan)
        server->chans = chan->next;

    if (server->current_chan == chan)
        sircc_ui_server_select_next_chan(server);
}

struct sircc_server *
sircc_server_get_current(void) {
    return sircc.servers[sircc.current_server];
}

bool
sircc_server_is_current(struct sircc_server *server) {
    return sircc_server_get_current() == server;
}

static void
sircc_initialize(void) {
    struct sigaction sigact;

    memset(&sigact, 0, sizeof(struct sigaction));
    sigact.sa_handler = sircc_signal_handler;
    sigaction(SIGINT, &sigact, &sircc.old_sigact_sigint);
    sigaction(SIGTERM, &sigact, &sircc.old_sigact_sigterm);
    sigaction(SIGWINCH, &sigact, &sircc.old_sigact_sigwinch);

    if (pipe(sircc.signal_pipe) == -1)
        die("cannot create pipe: %m");

    sircc.msg_handlers = ht_table_new(ht_hash_string, ht_equal_string);

    sircc_buf_init(&sircc.input_buf);
    sircc_buf_init(&sircc.prompt_buf);

    sircc_setup_poll_array();

    for (size_t i = 0; i < sircc.nb_servers; i++) {
        struct sircc_server *server;

        server = sircc.servers[i];

        sircc_server_prepare_connection(server);
        if (server->state == SIRCC_SERVER_BROKEN)
            continue;

        sircc_server_connect(server);
    }
}

static void
sircc_shutdown(void) {
    for (size_t i = 0; i < sircc.nb_servers; i++) {
        sircc_server_disconnect(sircc.servers[i]);
        sircc_server_delete(sircc.servers[i]);
    }
    sircc_free(sircc.servers);

    free(sircc.pollfds);

    close(sircc.signal_pipe[0]);
    close(sircc.signal_pipe[1]);

    ht_table_delete(sircc.msg_handlers);

    sircc_buf_free(&sircc.input_buf);
    sircc_buf_free(&sircc.prompt_buf);

    sigaction(SIGINT, &sircc.old_sigact_sigint, NULL);
    sigaction(SIGTERM, &sircc.old_sigact_sigterm, NULL);
    sigaction(SIGWINCH, &sircc.old_sigact_sigwinch, NULL);
}

static void
sircc_server_add(struct sircc_server *server) {
    if (!sircc.servers) {
        sircc.nb_servers = 1;
        sircc.servers = sircc_malloc(sizeof(struct sircc_server *));
        sircc.servers[0] = server;
    } else {
        size_t sz;

        sircc.nb_servers++;
        sz = sircc.nb_servers * sizeof(struct sircc_server *);
        sircc.servers = sircc_realloc(sircc.servers, sz);
        sircc.servers[sircc.nb_servers - 1] = server;
    }
}

static void
sircc_setup_poll_array(void) {
    free(sircc.pollfds);

    /* - 1 pollfd for the signal pipe.
     * - 1 pollfd for the stdin file descriptor.
     * - 1 pollfd for the socket of each server. */
    sircc.nb_pollfds = sircc.nb_servers + 2;
    sircc.pollfds = calloc(sircc.nb_pollfds, sizeof(struct pollfd));

    sircc.pollfds[0].fd = sircc.signal_pipe[0];
    sircc.pollfds[0].events = POLLIN;

    sircc.pollfds[1].fd = STDIN_FILENO;
    sircc.pollfds[1].events = POLLIN;

    for (size_t i = 0; i < sircc.nb_servers; i++) {
        struct sircc_server *server;

        server = sircc.servers[i];
        server->pollfd = &sircc.pollfds[i + 2];
    }
}

static void
sircc_poll(void) {
    if (poll(sircc.pollfds, sircc.nb_pollfds, -1) == -1) {
        if (errno == EINTR) {
            return;
        } else {
            die("cannot poll fds: %m");
        }
    }

    if (sircc.pollfds[0].revents & POLLIN)
        sircc_read_signal();

    if (sircc.pollfds[1].revents & POLLIN)
        sircc_read_input();

    for (size_t i = 0; i < sircc.nb_servers; i++) {
        struct sircc_server *server;
        int revents;

        server = sircc.servers[i];
        revents = sircc.pollfds[i + 2].revents;

        if (revents & POLLIN) {
            sircc_server_on_pollin(server);

            if (server->state == SIRCC_SERVER_DISCONNECTED) {
                /* If the pollin event handler closed the connection, we do not
                 * want to process any more event. */
                continue;
            }
        }

        if (revents & POLLOUT) {
            sircc_server_on_pollout(server);
        }
    }
}

static void
sircc_read_signal(void) {
    ssize_t ret;
    int signo;

    ret = read(sircc.signal_pipe[0], &signo, sizeof(int));
    if (ret < (ssize_t)sizeof(int))
        die("cannot read pipe: %m");

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
sircc_read_input(void) {
    static bool escape = false;

    struct sircc_server *server;
    ssize_t ret;
    unsigned char *ptr;
    size_t len;

    server = sircc_server_get_current();

    ret = sircc_buf_read(&sircc.input_buf, STDIN_FILENO, 64);
    if (ret < 0)
        die("cannot read terminal device: %m");
    if (ret == 0)
        die("eof on terminal device");

    len = sircc_buf_length(&sircc.input_buf);
    ptr = (unsigned char *)sircc_buf_data(&sircc.input_buf);

    for (size_t i = 0; i < len; i++) {
        unsigned char c;

        c = ptr[i];

        if (c == 8) {
            /* Backspace */
            sircc_ui_prompt_delete_previous_char();
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
            sircc_buf_add_printf(&sircc.prompt_buf, "%c", (char)c);
        }
    }

    sircc_buf_skip(&sircc.input_buf, len);

    sircc_ui_prompt_redraw();
    sircc_ui_update();
}

static void
sircc_set_msg_handler(const char *command, sircc_msg_handler handler) {
    ht_table_insert(sircc.msg_handlers, (void *)command, handler);
}

static void
sircc_on_msg_join(struct sircc_server *server, struct sircc_msg *msg) {
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
        sircc_chan_log_info(chan, "You have joined %s", chan_name);
        sircc_ui_server_select_chan(server, chan);
    } else {
        /* Someone else joined the chan */
        sircc_chan_log_info(chan, "%s has joined %s", nickname, chan_name);
    }
}

static void
sircc_on_msg_part(struct sircc_server *server, struct sircc_msg *msg) {
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
        sircc_chan_log_info(chan, "%s has left %s", nickname, chan_name);
    }
}

static void
sircc_on_msg_ping(struct sircc_server *server, struct sircc_msg *msg) {
    if (msg->nb_params < 1) {
        sircc_server_log_error(server, "missing argument in PING message");
        return;
    }

    sircc_server_printf(server, "PONG :%s\r\n", msg->params[0]);
}

static void
sircc_on_msg_privmsg(struct sircc_server *server, struct sircc_msg *msg) {
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

    sircc_chan_log_msg(chan, nickname, "%s", text);
}

static void
sircc_on_msg_topic(struct sircc_server *server, struct sircc_msg *msg) {
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
sircc_on_msg_rpl_welcome(struct sircc_server *server, struct sircc_msg *msg) {
    sircc_server_log_info(server, "registered");

    /* XXX debug */
    sircc_server_printf(server, "JOIN #test\r\n");
}

static void
sircc_on_msg_rpl_notopic(struct sircc_server *server, struct sircc_msg *msg) {
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
}

static void
sircc_on_msg_rpl_topic(struct sircc_server *server, struct sircc_msg *msg) {
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
}
