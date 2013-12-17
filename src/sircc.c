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
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "sircc.h"

typedef void (*sircc_msg_handler)(struct sircc_server *, struct sircc_msg *);


static void usage(const char *, int);

static void sircc_signal_handler(int);

static void sircc_initialize(void);
static void sircc_shutdown(void);
static void sircc_server_add(struct sircc_server *);
static void sircc_setup_poll_array(void);
static void sircc_poll(void);
static void sircc_set_msg_handler(const char *, sircc_msg_handler);

static void sircc_on_msg_ping(struct sircc_server *, struct sircc_msg *);


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

    sircc_initialize();

    sircc_set_msg_handler("PING", sircc_on_msg_ping);

    while (!sircc.do_exit) {
        sircc_poll();
    }

    sircc_shutdown();
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

struct sircc_server *
sircc_server_new(void) {
    struct sircc_server *server;

    server = sircc_malloc(sizeof(struct sircc_server));
    memset(server, 0, sizeof(struct sircc_server));

    server->sock = -1;

    sircc_buf_init(&server->rbuf);
    sircc_buf_init(&server->wbuf);

    server->state = SIRCC_SERVER_DISCONNECTED;

    return server;
}

void
sircc_server_delete(struct sircc_server *server) {
    if (!server)
        return;

    freeaddrinfo(server->addresses[0]);
    sircc_free(server->addresses);

    sircc_buf_free(&server->rbuf);
    sircc_buf_free(&server->wbuf);

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
    sircc_server_on_connection_established(server);
    return 0;
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

    server->state = SIRCC_SERVER_DISCONNECTED;
}

void
sircc_server_trace(struct sircc_server *server, const char *fmt, ...) {
    char buf[SIRCC_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    buf[strcspn(buf, "\r\n")] = '\0';

    /* XXX debug */
    printf("%-20s  %s\n", server->host, buf);
}

void
sircc_server_log_info(struct sircc_server *server, const char *fmt, ...) {
    char buf[SIRCC_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    buf[strcspn(buf, "\r\n")] = '\0';

    /* XXX debug */
    printf("%-20s  %s\n", server->host, buf);
}

void
sircc_server_log_error(struct sircc_server *server, const char *fmt, ...) {
    char buf[SIRCC_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    buf[strcspn(buf, "\r\n")] = '\0';

    /* XXX debug */
    printf("%-20s  %s\n", server->host, buf);
}

void
sircc_server_write(struct sircc_server *server, const char *buf, size_t sz) {
    sircc_buf_add(&server->wbuf, buf, sz);

    sircc_server_trace(server, "> %s", buf);

    server->pollfd->events |= POLLOUT;
}

int
sircc_server_vprintf(struct sircc_server *server, const char *fmt, va_list ap) {
    size_t old_len;

    old_len = sircc_buf_length(&server->wbuf);

    if (sircc_buf_add_vprintf(&server->wbuf, fmt, ap) == -1)
        return -1;

    sircc_server_trace(server, "> %s",
                       sircc_buf_data(&server->wbuf) + old_len);

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
                        sircc_server_trace(server, "< %s", ptr);
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
                sircc_server_on_connection_established(server);
            } else if (err == EINPROGRESS) {
                return;
            } else {
                sircc_server_log_error(server, "%s", sircc_get_error());
                sircc_server_disconnect(server);
            }
        }
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

    default:
        sircc_server_log_error(server, "ignoring pollout event in state %d",
                               server->state);
        break;
    }
}

void
sircc_server_on_connection_established(struct sircc_server *server) {
    sircc_server_log_info(server, "connected");

    server->pollfd->events = POLLIN;

    sircc_server_printf(server, "NICK %s\r\n",
                        server->nickname);
    sircc_server_printf(server, "USER %s 0 * :%s\r\n",
                        server->nickname, server->realname);
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
sircc_chan_new(struct sircc_server *server) {
    struct sircc_chan *chan;

    chan = sircc_malloc(sizeof(struct sircc_chan));
    memset(chan, 0, sizeof(struct sircc_chan));

    chan->server = server;

    return chan;
}

void
sircc_chan_delete(struct sircc_chan *chan) {
    if (!chan)
        return;

    sircc_free(chan);
}

static void
sircc_initialize(void) {
    struct sigaction sigact;

    memset(&sigact, 0, sizeof(struct sigaction));
    sigact.sa_handler = sircc_signal_handler;
    sigaction(SIGINT, &sigact, &sircc.old_sigact_sigint);
    sigaction(SIGTERM, &sigact, &sircc.old_sigact_sigterm);

    if (pipe(sircc.signal_pipe) == -1)
        die("cannot create pipe: %m");

    sircc.msg_handlers = ht_table_new(ht_hash_string, ht_equal_string);

    sircc_setup_poll_array();

    for (size_t i = 0; i < sircc.nb_servers; i++) {
        sircc_server_prepare_connection(sircc.servers[i]);
        sircc_server_connect(sircc.servers[i]);
    }
}

static void
sircc_shutdown(void) {
    for (size_t i = 0; i < sircc.nb_chans; i++)
        sircc_chan_delete(sircc.chans[i]);
    sircc_free(sircc.chans);

    for (size_t i = 0; i < sircc.nb_servers; i++) {
        sircc_server_disconnect(sircc.servers[i]);
        sircc_server_delete(sircc.servers[i]);
    }
    sircc_free(sircc.servers);

    free(sircc.pollfds);

    ht_table_delete(sircc.msg_handlers);

    close(sircc.signal_pipe[0]);
    close(sircc.signal_pipe[1]);

    sigaction(SIGINT, &sircc.old_sigact_sigint, NULL);
    sigaction(SIGTERM, &sircc.old_sigact_sigterm, NULL);
}

static void
sircc_server_add(struct sircc_server *server) {
    if (!sircc.servers) {
        sircc.nb_servers = 1;
        sircc.servers = malloc(sizeof(struct sircc_server *));
        sircc.servers[0] = server;
    } else {
        size_t sz;

        sircc.nb_servers++;
        sz = sircc.nb_servers * sizeof(struct sircc_server *);
        sircc.servers = realloc(sircc.servers, sz);
        sircc.servers[sircc.nb_servers - 1] = server;
    }
}

static void
sircc_setup_poll_array(void) {
    free(sircc.pollfds);

    /* One pollfd for each server, plus one for the signal pipe */
    sircc.nb_pollfds = sircc.nb_servers + 1;
    sircc.pollfds = calloc(sircc.nb_pollfds, sizeof(struct pollfd));

    sircc.pollfds[0].fd = sircc.signal_pipe[0];
    sircc.pollfds[0].events = POLLIN;

    for (size_t i = 0; i < sircc.nb_servers; i++) {
        struct sircc_server *server;

        server = sircc.servers[i];
        server->pollfd = &sircc.pollfds[i + 1];
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

    if (sircc.pollfds[0].revents & POLLIN) {
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
        }
    }

    for (size_t i = 0; i < sircc.nb_servers; i++) {
        struct sircc_server *server;
        int revents;

        server = sircc.servers[i];
        revents = sircc.pollfds[i + 1].revents;

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
sircc_set_msg_handler(const char *command, sircc_msg_handler handler) {
    ht_table_insert(sircc.msg_handlers, (void *)command, handler);
}

static void
sircc_on_msg_ping(struct sircc_server *server, struct sircc_msg *msg) {
    if (msg->nb_params < 1) {
        sircc_server_log_error(server, "missing argument in PING message");
        return;
    }

    sircc_server_printf(server, "PONG :%s\r\n", msg->params[0]);
}
