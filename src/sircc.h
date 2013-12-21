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

#ifndef SIRCC_SIRCC_H
#define SIRCC_SIRCC_H

#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>

#include <iconv.h>
#include <netdb.h>
#include <poll.h>

#include <curses.h>

#include "hashtable.h"

#define SIRCC_ERROR_BUFSZ 1024

/* Memory */
void *sircc_malloc(size_t);
void *sircc_calloc(size_t, size_t);
void *sircc_realloc(void *, size_t);
void sircc_free(void *);
char *sircc_strdup(const char *);
char *sircc_strndup(const char *, size_t);

/* String utils */
char *sircc_str_to_utf8(char *, size_t);

size_t strlcpy(char *, const char *, size_t);

/* Memory buffers */
struct sircc_buf {
    char *data;
    size_t sz;
    size_t skip;
    size_t len;
};

void sircc_buf_init(struct sircc_buf *);
void sircc_buf_free(struct sircc_buf *);
struct sircc_buf *sircc_buf_new(void);
void sircc_buf_delete(struct sircc_buf *);

char *sircc_buf_data(const struct sircc_buf *);
size_t sircc_buf_length(const struct sircc_buf *);
size_t sircc_buf_free_space(const struct sircc_buf *);

void sircc_buf_repack(struct sircc_buf *);
void sircc_buf_resize(struct sircc_buf *, size_t);
void sircc_buf_grow(struct sircc_buf *, size_t);
void sircc_buf_ensure_free_space(struct sircc_buf *, size_t);
void sircc_buf_clear(struct sircc_buf *);

void sircc_buf_add(struct sircc_buf *, const char *, size_t);
void sircc_buf_add_buf(struct sircc_buf *, const struct sircc_buf *);
int sircc_buf_add_vprintf(struct sircc_buf *, const char *, va_list);
int sircc_buf_add_printf(struct sircc_buf *, const char *, ...)
    __attribute__((format(printf, 2, 3)));

void sircc_buf_skip(struct sircc_buf *, size_t);
void sircc_buf_remove(struct sircc_buf *, size_t);

char *sircc_buf_dup(const struct sircc_buf *);
char *sircc_buf_dup_str(const struct sircc_buf *);

ssize_t sircc_buf_read(struct sircc_buf *, int, size_t);
ssize_t sircc_buf_write(struct sircc_buf *, int);

/* Network */
int sircc_address_resolve(const char *, const char *,
                          struct addrinfo ***, size_t *);
int sircc_socket_open(struct addrinfo *);
int sircc_socket_get_so_error(int, int *);

/* IRC */
struct sircc_msg {
    char *prefix;
    char *command;

    char **params;
    size_t nb_params;
};

void sircc_msg_free(struct sircc_msg *);
int sircc_msg_parse(struct sircc_msg *, struct sircc_buf *);

/* User interface */
void sircc_ui_initialize(void);
void sircc_ui_shutdown(void);
void sircc_ui_on_resize(void);

void sircc_ui_update(void);

void sircc_ui_topic_redraw(void);
void sircc_ui_main_redraw(void);
void sircc_ui_chans_redraw(void);
void sircc_ui_servers_redraw(void);
void sircc_ui_prompt_redraw(void);

void sircc_ui_select_server(int);
void sircc_ui_select_previous_server(void);
void sircc_ui_select_next_server(void);

void sircc_ui_prompt_delete_previous_char(void);
void sircc_ui_prompt_clear(void);
void sircc_ui_prompt_execute(void);

/* Main */
void die(const char *, ...)
    __attribute__((format(printf, 1, 2)));

const char *sircc_get_error();
void sircc_set_error(const char *, ...);

enum sircc_server_state {
    SIRCC_SERVER_DISCONNECTED,
    SIRCC_SERVER_CONNECTING,
    SIRCC_SERVER_CONNECTED,

    SIRCC_SERVER_BROKEN
};

struct sircc_server {
    const char *host;
    const char *port;
    const char *nickname;
    const char *realname;

    struct addrinfo **addresses;
    size_t nb_addresses;
    size_t next_address_idx;

    int sock;

    enum sircc_server_state state;

    struct pollfd *pollfd;

    struct sircc_buf rbuf;
    struct sircc_buf wbuf;
};

struct sircc_server *sircc_server_new(void);
void sircc_server_delete(struct sircc_server *);
int sircc_server_prepare_connection(struct sircc_server *);
int sircc_server_connect(struct sircc_server *);
void sircc_server_disconnect(struct sircc_server *);
void sircc_server_trace(struct sircc_server *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
void sircc_server_log_info(struct sircc_server *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
void sircc_server_log_error(struct sircc_server *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
void sircc_server_write(struct sircc_server *, const char *, size_t);
int sircc_server_vprintf(struct sircc_server *, const char *, va_list);
int sircc_server_printf(struct sircc_server *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
void sircc_server_on_pollin(struct sircc_server *);
void sircc_server_on_pollout(struct sircc_server *);
void sircc_server_on_connection_established(struct sircc_server *);
void sircc_server_msg_process(struct sircc_server *, struct sircc_msg *);

struct sircc_server *sircc_server_get_current(void);
bool sircc_server_is_current(struct sircc_server *);

struct sircc_chan {
    struct sircc_server *server;
};

struct sircc_chan *sircc_chan_new(struct sircc_server *);
void sircc_chan_delete(struct sircc_chan *);

struct sircc {
    struct sircc_server **servers;
    size_t nb_servers;
    int current_server;

    struct sircc_chan **chans;
    size_t nb_chans;

    struct pollfd *pollfds;
    size_t nb_pollfds;

    int signal_pipe[2];
    bool do_exit;

    struct sigaction old_sigact_sigint;
    struct sigaction old_sigact_sigterm;
    struct sigaction old_sigact_sigwinch;

    struct ht_table *msg_handlers;

    struct sircc_buf input_buf;
    struct sircc_buf prompt_buf;

    /* UI */
    bool ui_setup;

    WINDOW *win_topic;
    WINDOW *win_main;
    WINDOW *win_chans;
    WINDOW *win_servers;
    WINDOW *win_prompt;
};

extern struct sircc sircc;

#endif
