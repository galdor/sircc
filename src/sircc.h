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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dirent.h>
#include <fcntl.h>
#include <iconv.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <unistd.h>

#ifdef SIRCC_PLATFORM_DARWIN
#   include <sys/syslimits.h>
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>

#include <pcre.h>

#include <curses.h>

#ifdef SIRCC_WITH_X11
#   include <X11/Xlib.h>
#endif

#include <core.h>
#include <io.h>

#define SIRCC_NICKNAME_MAXSZ 32

/* Debug */
#ifdef NDEBUG
#   define sircc_debug_initialize 1
#   define sircc_debug_shutdown 1
#   define sircc_debug 1
#else
void sircc_debug_initialize(void);
void sircc_debug_shutdown(void);
void sircc_debug(const char *, ...)
    __attribute__((format(printf, 1, 2)));
#endif

/* Strings */
int sircc_is_breaking_space(int);

char *sircc_str_convert(char *, size_t, const char *, const char *, size_t *);
char *sircc_str_locale_to_utf8(char *, size_t, size_t *);

bool sircc_utf8_is_leading_byte(char);
bool sircc_utf8_is_continuation_byte(char);
size_t sircc_utf8_sequence_length(char);
size_t sircc_utf8_nb_chars(const char *);

/* Text processing */
int sircc_processing_initialize(void);
void sircc_processing_shutdown(void);

char *sircc_process_text(const char *, bool);

/* Memory buffers */
size_t c_buffer_utf8_nb_chars(const struct c_buffer *);
char *c_buffer_utf8_last_n_chars(const struct c_buffer *, size_t, size_t *);

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
    struct c_hash_table *entries;

    char **servers;
    size_t servers_sz;
    size_t nb_servers;
};

int sircc_cfg_initialize(const char *);
void sircc_cfg_shutdown(void);

void sircc_cfg_init(struct sircc_cfg *);
void sircc_cfg_free(struct sircc_cfg *);

int sircc_cfg_load_directory(struct sircc_cfg *, const char *);
int sircc_cfg_load_file(struct sircc_cfg *, const char *);

void sircc_cfg_ssl_file_path(char *, const char *, size_t);

const char *sircc_cfg_string(struct sircc_cfg *, const char *, const char *);
const char **sircc_cfg_strings(struct sircc_cfg *, const char *, size_t *);
int sircc_cfg_integer(struct sircc_cfg *, const char *, int);
bool sircc_cfg_boolean(struct sircc_cfg *, const char *, bool);

struct sircc_server;

const char *sircc_cfg_server_string(struct sircc_server *, const char *,
                                    const char *);
const char **sircc_cfg_server_strings(struct sircc_server *, const char *,
                                      size_t *);
int sircc_cfg_server_integer(struct sircc_server *, const char *, int);
bool sircc_cfg_server_boolean(struct sircc_server *, const char *, bool);

/* Layout */
struct sircc_history;
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
                                    struct sircc_history *,
                                    struct sircc_history_entry *);
void sircc_layout_skip_history_entry(struct sircc_layout *);

/* History */
enum sircc_history_entry_type {
    SIRCC_HISTORY_CHAN_MSG,
    SIRCC_HISTORY_SERVER_MSG,
    SIRCC_HISTORY_ACTION,
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

    bool disable_processing;
};

void sircc_history_init(struct sircc_history *, size_t sz);
void sircc_history_free(struct sircc_history *);

void sircc_history_add_entry(struct sircc_history *,
                             const struct sircc_history_entry *);
void sircc_history_add_chan_msg(struct sircc_history *, time_t, char *,
                                char *);
void sircc_history_add_server_msg(struct sircc_history *, time_t, char *,
                                  char *);
void sircc_history_add_action(struct sircc_history *, time_t, char *,
                              char *);
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

    time_t server_date; /* cap znc.in/server-time */
};

void sircc_msg_free(struct sircc_msg *);
int sircc_msg_parse(struct sircc_msg *, struct c_buffer *);
int sircc_msg_prefix_nickname(const struct sircc_msg *, char *, size_t);

bool sircc_irc_is_chan_prefix(int);

enum sircc_irc_cap_mod {
    SIRCC_CAP_NONE = 0,
    SIRCC_CAP_DISABLE,
    SIRCC_CAP_ACK,
    SIRCC_CAP_STICKY
};

struct sircc_irc_cap {
    char *name;
    enum sircc_irc_cap_mod modifier;
};

struct sircc_irc_cap *sircc_irc_caps_parse(const char *, size_t *);
void sircc_irc_caps_free(struct sircc_irc_cap *, size_t);

char *sircc_ctcp_quote(const char *);

#ifdef SIRCC_WITH_X11
/* X11 */
void sircc_x11_initialize(void);
void sircc_x11_shutdown(void);

char *sircc_x11_primary_selection(void);
#endif

/* Main */
void die(const char *, ...)
    __attribute__((format(printf, 1, 2)));

struct sircc_chan {
    char *name;
    struct sircc_server *server;

    struct sircc_history history;

    struct sircc_chan *prev;
    struct sircc_chan *next;

    char *topic;

    bool is_user;

    char **users;
    size_t nb_users;
    bool users_sorted;

    bool activity; /* true if there are unread messages */
};

struct sircc_chan *sircc_chan_new(struct sircc_server *, const char *);
void sircc_chan_delete(struct sircc_chan *);
void sircc_chan_set_topic(struct sircc_chan *, const char *);

struct sircc_history *sircc_chan_history(struct sircc_chan *);
bool sircc_chan_needs_redraw(struct sircc_chan *);
void sircc_chan_on_msg_added(struct sircc_chan *, bool);

void sircc_chan_log_info(struct sircc_chan *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
void sircc_chan_log_error(struct sircc_chan *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
void sircc_chan_add_msg(struct sircc_chan *, time_t, const char *,
                        const char *);
void sircc_chan_add_server_msg(struct sircc_chan *, time_t, const char *,
                               const char *);
void sircc_chan_add_action(struct sircc_chan *, time_t, const char *,
                           const char *);

void sircc_chan_add_user(struct sircc_chan *, const char *, size_t);
void sircc_chan_remove_user(struct sircc_chan *, const char *);
void sircc_chan_sort_users(struct sircc_chan *);
char *sircc_chan_next_user_completion(struct sircc_chan *,
                                      const char *, const char *);

struct sircc_server {
    const char *name;

    const char *host;
    uint16_t port;
    bool autoconnect;

    bool use_ssl;
    const char *ssl_ca_cert;

    struct io_tcp_client *tcp_client;

    const char *nickname;
    char *current_nickname;
    int max_nickname_length;
    const char *realname;
    const char *password;

    struct sircc_history history;

    struct sircc_chan *chans;
    struct sircc_chan *current_chan;
    struct sircc_chan *last_chan;

    bool cap_znc_server_time;
};

struct sircc_server *sircc_server_new(const char *name);
void sircc_server_delete(struct sircc_server *);

int sircc_server_connect(struct sircc_server *);
void sircc_server_disconnect(struct sircc_server *);

void sircc_server_trace(struct sircc_server *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
void sircc_server_log_info(struct sircc_server *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
void sircc_server_log_error(struct sircc_server *, const char *, ...)
    __attribute__((format(printf, 2, 3)));

void sircc_server_add_server_msg(struct sircc_server *, time_t, const char *,
                                 const char *);

void sircc_server_write(struct sircc_server *, const char *, size_t);
void sircc_server_vprintf(struct sircc_server *, const char *, va_list);
void sircc_server_printf(struct sircc_server *, const char *, ...)
    __attribute__((format(printf, 2, 3)));

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

struct sircc_highlighter {
    pcre *regexp;
    pcre_extra *regexp_extra;

    char *sequence;
};

struct sircc {
    struct c_ptr_vector *servers;
    ssize_t current_server;

    struct io_base *io_base;

    bool do_exit;

    struct sigaction old_sigact_sigint;
    struct sigaction old_sigact_sigterm;
    struct sigaction old_sigact_sigwinch;

    struct c_hash_table *msg_handlers;

    const char *cfgdir;
    struct sircc_cfg cfg;

    /* UI */
    bool ui_setup;

    WINDOW *win_topic;
    WINDOW *win_main;
    WINDOW *win_chans;
    WINDOW *win_servers;
    WINDOW *win_prompt;

    struct c_buffer *input_read_buf;
    struct c_buffer *input_buf;

    bool completion; /* is completion in progress */
    size_t completion_offset;
    char *completion_prefix;
    char *last_completion;

    struct c_buffer *prompt_buf;
    size_t prompt_cursor;  /* offset in prompt_buf */
    size_t prompt_vcursor; /* position in the window */

    struct sircc_highlighter *highlighters;
    size_t nb_highlighters;

#ifdef SIRCC_WITH_X11
    /* X11 */
    Display *display;
    Window window;

    Atom atom_utf8_string;
    Atom atom_sircc_selection;
#endif
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

void sircc_ui_server_select(ssize_t);
void sircc_ui_server_select_previous(void);
void sircc_ui_server_select_next(void);
void sircc_ui_server_select_chan(struct sircc_server *, struct sircc_chan *);
void sircc_ui_server_select_previous_chan(struct sircc_server *);
void sircc_ui_server_select_next_chan(struct sircc_server *);

void sircc_ui_prompt_add(const char *);
void sircc_ui_prompt_add_selection(void);
void sircc_ui_prompt_delete_previous_char(void);
void sircc_ui_prompt_delete_from_cursor(void);
void sircc_ui_prompt_move_cursor_backward(void);
void sircc_ui_prompt_move_cursor_forward(void);
void sircc_ui_prompt_move_cursor_beginning(void);
void sircc_ui_prompt_move_cursor_end(void);
void sircc_ui_prompt_clear(void);
void sircc_ui_prompt_execute(void);

int sircc_ui_write(WINDOW *, const char *, size_t);
int sircc_ui_vprintf(WINDOW *, const char *, va_list);
int sircc_ui_printf(WINDOW *, const char *, ...);

void sircc_ui_completion_reset(void);
void sircc_ui_completion_next(void);
void sircc_ui_completion_update_prompt(const char *, const char *);

/* Commands */
enum sircc_cmd_id {
    SIRCC_CMD_HELP = 0,
    SIRCC_CMD_JOIN,
    SIRCC_CMD_ME,
    SIRCC_CMD_MODE,
    SIRCC_CMD_MSG,
    SIRCC_CMD_NAMES,
    SIRCC_CMD_NICK,
    SIRCC_CMD_PART,
    SIRCC_CMD_QUIT,
    SIRCC_CMD_QUOTE,
    SIRCC_CMD_TOPIC,

    SIRCC_CMD_COUNT
};

struct sircc_cmd {
    enum sircc_cmd_id id;

    size_t nb_args;
    char **args;
};

void sircc_cmd_free(struct sircc_cmd *);
int sircc_cmd_parse(struct sircc_cmd *, struct c_buffer *);
void sircc_cmd_run(struct sircc_cmd *cmd);

char *sircc_cmd_next_completion(const char *, const char *);

#endif
