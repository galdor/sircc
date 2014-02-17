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
#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <dirent.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#ifdef SIRCC_PLATFORM_FREEBSD
#   include <sys/signal.h> /* Required for SIGWINCH */
#endif

#include "sircc.h"

static void sircc_usage(const char *, int);
static void sircc_version(void);

static void sircc_signal_handler(int);

static void sircc_initialize(void);
static void sircc_shutdown(void);
static void sircc_load_servers(void);
static void sircc_server_add(struct sircc_server *);
static void sircc_setup_poll_array(void);
static void sircc_poll(void);
static void sircc_read_signal(void);
static void sircc_read_input(void);

static int sircc_cmp_users(const void *, const void *);


static struct ht_memory_allocator sircc_ht_allocator = {
    .malloc = sircc_malloc,
    .calloc = sircc_calloc,
    .realloc = sircc_realloc,
    .free = sircc_free
};

static struct bf_memory_allocator sircc_bf_allocator = {
    .malloc = sircc_malloc,
    .calloc = sircc_calloc,
    .realloc = sircc_realloc,
    .free = sircc_free
};

__thread char sircc_error_buf[SIRCC_ERROR_BUFSZ];

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

    ht_set_memory_allocator(&sircc_ht_allocator);
    bf_set_memory_allocator(&sircc_bf_allocator);

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
        die("%s", sircc_get_error());

    if (sircc_processing_initialize() == -1)
        die("%s", sircc_get_error());

    sircc_load_servers();
    sircc_ui_initialize();
    sircc_initialize();

#ifdef SIRCC_WITH_X11
    sircc_x11_initialize();
#endif

    while (!sircc.do_exit)
        sircc_poll();

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

    assert(strlen(name) > 0);

    chan = sircc_malloc(sizeof(struct sircc_chan));
    memset(chan, 0, sizeof(struct sircc_chan));

    chan->name = sircc_strdup(name);
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
    sircc_free(chan->name);
    sircc_free(chan->topic);

    for (size_t i = 0; i < chan->nb_users; i++)
        sircc_free(chan->users[i]);
    sircc_free(chan->users);

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
    sircc_vasprintf(&str, fmt, ap);
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
    sircc_vasprintf(&str, fmt, ap);
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
    sircc_history_add_chan_msg(history, date, sircc_strdup(src),
                               sircc_strdup(text));

    sircc_chan_on_msg_added(chan, true);
}

void
sircc_chan_add_server_msg(struct sircc_chan *chan, time_t date,
                          const char *src, const char *text) {
    struct sircc_history *history;

    history = sircc_chan_history(chan);
    sircc_history_add_server_msg(history, date, sircc_strdup(src),
                                 sircc_strdup(text));

    sircc_chan_on_msg_added(chan, true);
}

void
sircc_chan_add_action(struct sircc_chan *chan, time_t date, const char *src,
                      const char *text) {
    struct sircc_history *history;

    history = sircc_chan_history(chan);
    sircc_history_add_action(history, date, sircc_strdup(src),
                             sircc_strdup(text));

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
        chan->users = sircc_malloc(sizeof(char *));
    } else {
        chan->users = sircc_realloc(chan->users,
                                    (chan->nb_users + 1) * sizeof(char *));
    }

    chan->users[chan->nb_users] = sircc_strndup(user, sz);
    chan->nb_users++;

    chan->users_sorted = false;
}

void
sircc_chan_remove_user(struct sircc_chan *chan, const char *user) {
    for (size_t i = 0; i < chan->nb_users; i++) {
        if (strcmp(chan->users[i], user) == 0) {
            sircc_free(chan->users[i]);

            if (i < chan->nb_users - 1) {
                memmove(chan->users + i, chan->users + i + 1,
                        (chan->nb_users - i - 1) * sizeof(char *));
            }

            chan->nb_users--;
            if (chan->nb_users == 0) {
                sircc_free(chan->users);
                chan->users = NULL;
            } else {
                chan->users = sircc_realloc(chan->users,
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

                return sircc_strdup(next_completion);
            }
        }
    }

    return NULL;
}

struct sircc_server *
sircc_server_new(const char *name) {
    struct sircc_server *server;

    server = sircc_malloc(sizeof(struct sircc_server));
    memset(server, 0, sizeof(struct sircc_server));

    server->name = name;

    server->sock = -1;

    server->rbuf = bf_buffer_new(128);
    server->wbuf = bf_buffer_new(128);

    server->max_nickname_length = 15;

    sircc_history_init(&server->history, 1024);
    server->history.max_nickname_length = server->max_nickname_length;

    server->state = SIRCC_SERVER_DISCONNECTED;

    return server;
}

void
sircc_server_delete(struct sircc_server *server) {
    struct sircc_chan *chan;

    if (!server)
        return;

    sircc_free(server->current_nickname);

    if (server->addresses) {
        freeaddrinfo(server->addresses[0]);
        sircc_free(server->addresses);
    }

    bf_buffer_delete(server->rbuf);
    bf_buffer_delete(server->wbuf);

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

    if (server->ssl_verify_certificate) {
        ret = sircc_server_ssl_check_certificate(server);
        if (ret <= 0)
            goto error;
    }

    server->state = SIRCC_SERVER_SSL_CONNECTED;
    sircc_server_on_connection_established(server);
    return 0;

error:
    sircc_server_log_info(server, "closing connection");

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

    bf_buffer_clear(server->rbuf);
    bf_buffer_clear(server->wbuf);

    if (server->ssl_ctx) {
        SSL_CTX_free(server->ssl_ctx);
        server->ssl_ctx = NULL;
    }

    if (server->ssl) {
        SSL_free(server->ssl);
        server->ssl = NULL;
    }

    server->state = SIRCC_SERVER_DISCONNECTED;
}

int
sircc_server_ssl_check_certificate(struct sircc_server *server) {
    X509 *cert;
    X509_NAME *name;
    X509_STORE *store;
    X509_STORE_CTX *store_ctx;
    char path[PATH_MAX];
    char buf[512];

    cert = SSL_get_peer_certificate(server->ssl);
    if (!cert) {
        sircc_server_log_error(server, "cannot get peer ssl certificate");
        return -1;
    }

    name = X509_get_issuer_name(cert);
    X509_NAME_oneline(name, buf, sizeof(buf));
    sircc_server_log_info(server, "ssl certificate issuer: %s", buf);

    name = X509_get_subject_name(cert);
    X509_NAME_oneline(name, buf, sizeof(buf));
    sircc_server_log_info(server, "ssl certificate subject: %s", buf);

    store = NULL;
    store_ctx = NULL;

    store = X509_STORE_new();
    if (!store) {
        sircc_server_log_error(server, "cannot create x509 store: %s",
                               sircc_ssl_get_error());
        goto error;
    }

    sircc_cfg_ssl_file_path(path, server->ssl_ca_certificate, sizeof(path));
    sircc_server_log_info(server, "loading ssl ca certificate from %s", path);

    if (sircc_x509_store_add_certificate(store, path) == -1) {
        sircc_server_log_error(server, "%s", sircc_get_error());
        goto error;
    }

    store_ctx = X509_STORE_CTX_new();
    if (!store_ctx) {
        sircc_server_log_error(server, "cannot create x509 store context: %s",
                               sircc_ssl_get_error());
        goto error;
    }

    if (X509_STORE_CTX_init(store_ctx, store, cert, NULL) == 0) {
        sircc_server_log_error(server,
                               "cannot initialize x509 store context: %s",
                               sircc_ssl_get_error());
        goto error;
    }

    if (X509_verify_cert(store_ctx) <= 0) {
        int cert_err;

        cert_err = X509_STORE_CTX_get_error(store_ctx);
        if (cert_err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
            && server->ssl_allow_self_signed_certificate) {
            sircc_server_log_info(server,
                                  "accepting self signed ssl certificate");
        } else {
            const char *cert_errstr;

            cert_errstr = X509_verify_cert_error_string(cert_err);
            sircc_server_log_error(server,
                                   "ssl certificate verification failed: %s"
                                   " (error %d)", cert_errstr, cert_err);

            X509_STORE_CTX_free(store_ctx);
            X509_STORE_free(store);
            return 0;
        }
    }

    sircc_server_log_info(server, "ssl certificate verified");

    X509_STORE_CTX_free(store_ctx);
    X509_STORE_free(store);
    return 1;

error:
    if (store_ctx)
        X509_STORE_CTX_free(store_ctx);
    if (store)
        X509_STORE_free(store);
    return -1;
}

void
sircc_server_trace(struct sircc_server *server, const char *fmt, ...) {
    struct bf_buffer *buf;
    va_list ap;

    if (!server)
        server = sircc_server_get_current();

    buf = bf_buffer_new(128);

    va_start(ap, fmt);
    bf_buffer_add_vprintf(buf, fmt, ap);
    va_end(ap);

    sircc_history_add_trace(&server->history, bf_buffer_dup_string(buf));
    bf_buffer_delete(buf);

    if (server == sircc_server_get_current()) {
        sircc_ui_main_redraw();
        sircc_ui_update();
    }
}

void
sircc_server_log_info(struct sircc_server *server, const char *fmt, ...) {
    struct bf_buffer *buf;
    va_list ap;

    if (!server)
        server = sircc_server_get_current();

    buf = bf_buffer_new(128);

    va_start(ap, fmt);
    bf_buffer_add_vprintf(buf, fmt, ap);
    va_end(ap);

    sircc_history_add_info(&server->history, bf_buffer_dup_string(buf));
    bf_buffer_delete(buf);

    if (server == sircc_server_get_current()) {
        sircc_ui_main_redraw();
        sircc_ui_update();
    }
}

void
sircc_server_log_error(struct sircc_server *server, const char *fmt, ...) {
    struct bf_buffer *buf;
    va_list ap;

    if (!server)
        server = sircc_server_get_current();

    buf = bf_buffer_new(128);

    va_start(ap, fmt);
    bf_buffer_add_vprintf(buf, fmt, ap);
    va_end(ap);

    sircc_history_add_error(&server->history, bf_buffer_dup_string(buf));
    bf_buffer_delete(buf);

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

    sircc_history_add_server_msg(&server->history, date, sircc_strdup(src),
                                 sircc_strdup(msg));

    if (server == sircc_server_get_current()) {
        sircc_ui_main_redraw();
        sircc_ui_update();
    }
}

void
sircc_server_write(struct sircc_server *server, const char *buf, size_t sz) {
    if (server->state == SIRCC_SERVER_DISCONNECTED
     || server->state == SIRCC_SERVER_BROKEN) {
        sircc_server_log_error(server, "disconnected from server");
        return;
    }

    bf_buffer_add(server->wbuf, buf, sz);

    server->pollfd->events |= POLLOUT;
}

int
sircc_server_vprintf(struct sircc_server *server, const char *fmt, va_list ap) {
    if (server->state == SIRCC_SERVER_DISCONNECTED
     || server->state == SIRCC_SERVER_BROKEN) {
        sircc_server_log_error(server, "disconnected from server");
        return -1;
    }

    if (bf_buffer_add_vprintf(server->wbuf, fmt, ap) == -1)
        return -1;

    server->pollfd->events |= POLLOUT;
    return 0;
}

int
sircc_server_printf(struct sircc_server *server, const char *fmt, ...) {
    va_list ap;
    int ret;

    if (server->state == SIRCC_SERVER_DISCONNECTED
     || server->state == SIRCC_SERVER_BROKEN) {
        sircc_server_log_error(server, "disconnected from server");
        return -1;
    }

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

            ret = bf_buffer_read(server->rbuf, server->sock, BUFSIZ);
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

            bf_buffer_add(server->rbuf, buf, (size_t)ret);
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

            ret = bf_buffer_write(server->wbuf, server->sock);
            if (ret == -1) {
                sircc_server_log_error(server, "cannot write to socket: %m");
                sircc_server_disconnect(server);
            }

            if (bf_buffer_length(server->wbuf) == 0)
                server->pollfd->events &= ~POLLOUT;
        }
        break;

    case SIRCC_SERVER_SSL_CONNECTED:
        {
            const char *data;
            int len, ret, err;

            data = bf_buffer_data(server->wbuf);

            if (server->ssl_last_write_length > 0) {
                len = server->ssl_last_write_length;
            } else {
                len = (int)bf_buffer_length(server->wbuf);
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

            bf_buffer_skip(server->wbuf, (size_t)ret);
            if (bf_buffer_length(server->wbuf) == 0)
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

    sircc_server_printf(server, "CAP LS\r\n");
    if (server->password)
        sircc_server_printf(server, "PASS %s\r\n", server->password);
    sircc_server_printf(server, "NICK %s\r\n", server->nickname);
    sircc_server_printf(server, "USER %s 0 * :%s\r\n",
                        server->nickname, server->realname);
}

void
sircc_server_read_msgs(struct sircc_server *server) {
    while (bf_buffer_length(server->rbuf) > 0) {
        struct sircc_msg msg;
        int ret;

        {
            const char *ptr;
            char *cr;

            ptr = bf_buffer_data(server->rbuf);

            cr = strchr(ptr, '\r');
            if (cr) {
                *cr = '\0';
                sircc_server_trace(server, "%s", ptr);
                *cr = '\r';
            }
        }

        ret = sircc_msg_parse(&msg, server->rbuf);
        if (ret == -1) {
            sircc_server_log_error(server, "cannot parse message: %s",
                                   sircc_get_error());
            sircc_server_disconnect(server);
            return;
        }

        if (ret == 0)
            break;

        bf_buffer_skip(server->rbuf, (size_t)ret);

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
    if (sircc.current_server >= 0) {
        return sircc.servers[sircc.current_server];
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
    struct sigaction sigact;

    memset(&sigact, 0, sizeof(struct sigaction));
    sigact.sa_handler = sircc_signal_handler;
    sigaction(SIGINT, &sigact, &sircc.old_sigact_sigint);
    sigaction(SIGTERM, &sigact, &sircc.old_sigact_sigterm);
    sigaction(SIGWINCH, &sigact, &sircc.old_sigact_sigwinch);

    if (pipe(sircc.signal_pipe) == -1)
        die("cannot create pipe: %m");

    sircc.msg_handlers = ht_table_new(ht_hash_string, ht_equal_string);
    sircc_init_msg_handlers();

    sircc.input_buf = bf_buffer_new(0);
    sircc.input_read_buf = bf_buffer_new(0);
    sircc.prompt_buf = bf_buffer_new(0);

    sircc_setup_poll_array();

    for (size_t i = 0; i < sircc.nb_servers; i++) {
        struct sircc_server *server;

        server = sircc.servers[i];

        sircc_server_prepare_connection(server);
        if (server->state == SIRCC_SERVER_BROKEN)
            continue;

        if (server->autoconnect)
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

    bf_buffer_delete(sircc.input_read_buf);
    bf_buffer_delete(sircc.input_buf);
    bf_buffer_delete(sircc.prompt_buf);

    sigaction(SIGINT, &sircc.old_sigact_sigint, NULL);
    sigaction(SIGTERM, &sircc.old_sigact_sigterm, NULL);
    sigaction(SIGWINCH, &sircc.old_sigact_sigwinch, NULL);
}

static void
sircc_load_servers(void) {
    for (size_t i = 0; i < sircc.cfg.nb_servers; i++) {
        struct sircc_server *server;

        server = sircc_server_new(sircc.cfg.servers[i]);

        server->autoconnect = sircc_cfg_server_boolean(server, "autoconnect",
                                                       true);

        server->host = sircc_cfg_server_string(server, "host", NULL);
        server->port = sircc_cfg_server_string(server, "port", "6667");

        server->use_ssl = sircc_cfg_server_boolean(server, "ssl", false);
        if (server->use_ssl) {
            server->ssl_verify_certificate
                = sircc_cfg_server_boolean(server, "ssl_verify_certificate", true);

            server->ssl_ca_certificate
                = sircc_cfg_server_string(server, "ssl_ca_certificate", NULL);

            server->ssl_allow_self_signed_certificate
                = sircc_cfg_server_boolean(server, "ssl_allow_self_signed_certificate",
                                           false);
            if (server->ssl_verify_certificate && !server->ssl_ca_certificate)
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

        server->current_nickname = sircc_strdup(server->nickname);

        sircc_server_add(server);
    }

    if (sircc.nb_servers == 0)
        die("no server defined in configuration");
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

    ret = bf_buffer_read(sircc.input_read_buf, STDIN_FILENO, 64);
    if (ret < 0)
        die("cannot read terminal device: %m");
    if (ret == 0)
        die("eof on terminal device");

    len = bf_buffer_length(sircc.input_read_buf);
    ptr = (unsigned char *)bf_buffer_data(sircc.input_read_buf);

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
            bf_buffer_add(sircc.input_buf, (char *)&c, 1);
        }
    }

    {
        char *utf8_str;
        size_t nb_bytes;

        utf8_str = sircc_str_locale_to_utf8(bf_buffer_data(sircc.input_buf),
                                            bf_buffer_length(sircc.input_buf),
                                            &nb_bytes);
        if (!utf8_str) {
            sircc_chan_log_error(NULL, "cannot convert input to UTF-8: %s",
                                 sircc_get_error());

            bf_buffer_clear(sircc.input_read_buf);
            bf_buffer_clear(sircc.input_buf);
        }

        sircc_ui_prompt_add(utf8_str);
        sircc_free(utf8_str);

        /* If there is a truncated multibyte character at the end of
         * input_buf, it will stay in it to be completed the next time there
         * is something to read on stdin. */
        bf_buffer_skip(sircc.input_buf, nb_bytes);
    }

    bf_buffer_clear(sircc.input_read_buf);
}

static int
sircc_cmp_users(const void *p1, const void *p2) {
    const char **u1, **u2;

    u1 = (const char **)p1;
    u2 = (const char **)p2;

    return strcmp(*u1, *u2);
}
