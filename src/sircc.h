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

#ifndef SIRCC_SIRCC_H
#define SIRCC_SIRCC_H

#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>

#include <iconv.h>
#include <netdb.h>
#include <poll.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>

#include <curses.h>

#include "hashtable.h"

#define SIRCC_ERROR_BUFSZ 1024

#define SIRCC_NICKNAME_MAXSZ 32

/* Memory */
void *sircc_malloc(size_t);
void *sircc_calloc(size_t, size_t);
void *sircc_realloc(void *, size_t);
void sircc_free(void *);

/* String utils */
char *sircc_strdup(const char *);
char *sircc_strndup(const char *, size_t);

int sircc_vasprintf(char **, const char *, va_list);
int sircc_asprintf(char **, const char *, ...)
    __attribute__((format(printf, 2, 3)));

char *sircc_str_to_utf8(char *, size_t, size_t *);

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

/* Configuration */
enum sircc_cfg_entry_type {
    SIRCC_CFG_STRING,
    SIRCC_CFG_STRING_LIST,
    SIRCC_CFG_INTEGER,
    SIRCC_CFG_BOOLEAN
};

struct sircc_cfg_entry {
    char *key;

    enum sircc_cfg_entry_type type;

    union {
        char *s;
        struct {
            char **strs;
            size_t nb;
        } sl;
        int i;
        bool b;
    } u;
};

struct sircc_cfg {
    struct ht_table *entries;

    char **servers;
    size_t servers_sz;
    size_t nb_servers;
};

int sircc_cfg_initialize(const char *);
void sircc_cfg_shutdown(void);

void sircc_cfg_init(struct sircc_cfg *);
void sircc_cfg_free(struct sircc_cfg *);

int sircc_cfg_load_default(struct sircc_cfg *);
int sircc_cfg_load_directory(struct sircc_cfg *, const char *);
int sircc_cfg_load_file(struct sircc_cfg *, const char *);

void sircc_cfg_ssl_file_path(char *, const char *, size_t);

const char *sircc_cfg_string(struct sircc_cfg *, const char *,
                             const char *, ...)
    __attribute__((format(printf, 3, 4)));
const char **sircc_cfg_strings(struct sircc_cfg *, size_t *,
                               const char *, ...)
    __attribute__((format(printf, 3, 4)));
int sircc_cfg_integer(struct sircc_cfg *, int, const char *, ...)
    __attribute__((format(printf, 3, 4)));
bool sircc_cfg_boolean(struct sircc_cfg *, bool, const char *, ...)
    __attribute__((format(printf, 3, 4)));

struct sircc_server;

const char *sircc_cfg_server_string(struct sircc_server *, const char *,
                                    const char *);
const char **sircc_cfg_server_strings(struct sircc_server *, const char *,
                                      size_t *);
int sircc_cfg_server_integer(struct sircc_server *, const char *, int);
bool sircc_cfg_server_boolean(struct sircc_server *, const char *, bool);

/* Layout */
struct sircc_history_entry;

struct sircc_layout_row {
    const char *margin_text; /* timestamp and nickname */
    const char *text;        /* point to some text in a history entry */
    size_t text_sz;

    struct sircc_history_entry *entry;
    bool is_entry_first_row; /* true if the row is the first row of an entry */
};

struct sircc_layout {
    struct sircc_layout_row *rows;
    size_t rows_sz;
    size_t nb_rows;
    size_t start_idx;

    bool dirty; /* true if the layout needs to be recomputed (after a resize) */
};

void sircc_layout_init(struct sircc_layout *);
void sircc_layout_free(struct sircc_layout *);

void sircc_layout_add_row(struct sircc_layout *,
                          const struct sircc_layout_row *);

void sircc_layout_add_history_entry(struct sircc_layout *,
                                    struct sircc_history_entry *);
void sircc_layout_skip_history_entry(struct sircc_layout *);

/* History */
enum sircc_history_entry_type {
    SIRCC_HISTORY_CHAN_MSG,
    SIRCC_HISTORY_SERVER_MSG,
    SIRCC_HISTORY_TRACE,
    SIRCC_HISTORY_INFO,
    SIRCC_HISTORY_ERROR,
};

struct sircc_history_entry {
    enum sircc_history_entry_type type;

    time_t date;
    char *src;         /* The source nickname for SIRCC_HISTORY_CHAN_MSG */
    char *margin_text; /* Formatted date and src */
    char *text;
};

struct sircc_history {
    struct sircc_history_entry *entries;
    size_t sz;

    size_t nb_entries;
    size_t start_idx;

    struct sircc_layout layout;

    int max_nickname_length;
};

void sircc_history_init(struct sircc_history *, size_t sz);
void sircc_history_free(struct sircc_history *);

void sircc_history_add_entry(struct sircc_history *,
                             const struct sircc_history_entry *);
void sircc_history_add_chan_msg(struct sircc_history *, char *, char *);
void sircc_history_add_server_msg(struct sircc_history *, char *, char *);
void sircc_history_add_trace(struct sircc_history *, char *);
void sircc_history_add_info(struct sircc_history *, char *);
void sircc_history_add_error(struct sircc_history *, char *);

void sircc_history_recompute_layout(struct sircc_history *);
size_t sircc_history_margin_size(struct sircc_history *);

/* Network */
int sircc_address_resolve(const char *, const char *,
                          struct addrinfo ***, size_t *);
int sircc_socket_open(struct addrinfo *);
int sircc_socket_get_so_error(int, int *);

/* SSL */
const char *sircc_ssl_get_error(void);
int sircc_x509_store_add_certificate(X509_STORE *, const char *);

/* IRC */
struct sircc_msg {
    char *prefix;
    char *command;

    char **params;
    size_t nb_params;
};

void sircc_msg_free(struct sircc_msg *);
int sircc_msg_parse(struct sircc_msg *, struct sircc_buf *);
int sircc_msg_prefix_nickname(const struct sircc_msg *, char *, size_t);

bool sircc_irc_is_chan_prefix(int);

/* Main */
void die(const char *, ...)
    __attribute__((format(printf, 1, 2)));

const char *sircc_get_error();
void sircc_set_error(const char *, ...);

struct sircc_chan {
    char *name;
    struct sircc_server *server;

    struct sircc_history history;

    struct sircc_chan *prev;
    struct sircc_chan *next;

    char *topic;

    bool is_user;
};

struct sircc_chan *sircc_chan_new(struct sircc_server *, const char *);
void sircc_chan_delete(struct sircc_chan *);
void sircc_chan_set_topic(struct sircc_chan *, const char *);

void sircc_chan_log_info(struct sircc_chan *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
void sircc_chan_log_error(struct sircc_chan *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
void sircc_chan_add_msg(struct sircc_chan *, const char *, const char *);
void sircc_chan_add_server_msg(struct sircc_chan *, const char *, const char *);

enum sircc_server_state {
    SIRCC_SERVER_DISCONNECTED,
    SIRCC_SERVER_CONNECTING,
    SIRCC_SERVER_CONNECTED,
    SIRCC_SERVER_SSL_CONNECTING,
    SIRCC_SERVER_SSL_CONNECTED,

    SIRCC_SERVER_BROKEN
};

struct sircc_server {
    const char *name;

    const char *host;
    const char *port;
    bool autoconnect;
    bool use_ssl;

    const char *nickname;
    char *current_nickname;
    int max_nickname_length;
    const char *realname;
    const char *password;

    struct addrinfo **addresses;
    size_t nb_addresses;
    size_t next_address_idx;

    int sock;

    enum sircc_server_state state;

    struct pollfd *pollfd;

    struct sircc_buf rbuf;
    struct sircc_buf wbuf;

    struct sircc_history history;

    struct sircc_chan *chans;
    struct sircc_chan *current_chan;
    struct sircc_chan *last_chan;

    SSL_CTX *ssl_ctx;
    SSL *ssl;
    int ssl_last_write_length;
    bool ssl_verify_certificate;
    const char *ssl_ca_certificate;
    bool ssl_allow_self_signed_certificate;
};

struct sircc_server *sircc_server_new(const char *name);
void sircc_server_delete(struct sircc_server *);
int sircc_server_prepare_connection(struct sircc_server *);
int sircc_server_connect(struct sircc_server *);
int sircc_server_ssl_connect(struct sircc_server *);
void sircc_server_disconnect(struct sircc_server *);
int sircc_server_ssl_check_certificate(struct sircc_server *);
void sircc_server_trace(struct sircc_server *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
void sircc_server_log_info(struct sircc_server *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
void sircc_server_log_error(struct sircc_server *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
void sircc_server_add_server_msg(struct sircc_server *, const char *,
                                 const char *);
void sircc_server_write(struct sircc_server *, const char *, size_t);
int sircc_server_vprintf(struct sircc_server *, const char *, va_list);
int sircc_server_printf(struct sircc_server *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
void sircc_server_on_pollin(struct sircc_server *);
void sircc_server_on_pollout(struct sircc_server *);
void sircc_server_on_connection_established(struct sircc_server *);
void sircc_server_read_msgs(struct sircc_server *);
void sircc_server_msg_process(struct sircc_server *, struct sircc_msg *);

struct sircc_chan *sircc_server_get_chan(struct sircc_server *, const char *);
bool sircc_chan_is_current(struct sircc_chan *);
void sircc_server_add_chan(struct sircc_server *, struct sircc_chan *);
void sircc_server_remove_chan(struct sircc_server *, struct sircc_chan *);

struct sircc_server *sircc_server_get_current(void);
bool sircc_server_is_current(struct sircc_server *);

void sircc_server_send_privmsg(struct sircc_server *, const char *,
                               const char *);

struct sircc {
    struct sircc_server **servers;
    size_t nb_servers;
    int current_server;

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

    const char *cfgdir;
    struct sircc_cfg cfg;

    /* UI */
    bool ui_setup;

    WINDOW *win_topic;
    WINDOW *win_main;
    WINDOW *win_chans;
    WINDOW *win_servers;
    WINDOW *win_prompt;
};

extern struct sircc sircc;

/* Messages */
void sircc_init_msg_handlers(void);
void sircc_call_msg_handler(struct sircc_server *, struct sircc_msg *);

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

int sircc_ui_main_window_width(void);

void sircc_ui_server_select(int);
void sircc_ui_server_select_previous(void);
void sircc_ui_server_select_next(void);
void sircc_ui_server_select_chan(struct sircc_server *, struct sircc_chan *);
void sircc_ui_server_select_previous_chan(struct sircc_server *);
void sircc_ui_server_select_next_chan(struct sircc_server *);

void sircc_ui_prompt_delete_previous_char(void);
void sircc_ui_prompt_clear(void);
void sircc_ui_prompt_execute(void);

int sircc_ui_vformat(WINDOW *, const char *, va_list);
int sircc_ui_format(WINDOW *, const char *, ...);

/* Commands */
enum sircc_cmd_id {
    SIRCC_CMD_HELP = 0,
    SIRCC_CMD_JOIN,
    SIRCC_CMD_MODE,
    SIRCC_CMD_MSG,
    SIRCC_CMD_NAMES,
    SIRCC_CMD_NICK,
    SIRCC_CMD_PART,
    SIRCC_CMD_QUIT,
    SIRCC_CMD_TOPIC,

    SIRCC_CMD_COUNT
};

struct sircc_cmd {
    enum sircc_cmd_id id;

    size_t nb_args;
    char **args;
};

void sircc_cmd_free(struct sircc_cmd *);
int sircc_cmd_parse(struct sircc_cmd *, struct sircc_buf *);
void sircc_cmd_run(struct sircc_cmd *cmd);

#endif
