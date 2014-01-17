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
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "sircc.h"

static char *sircc_ui_completion_prefix(size_t *);

static void sircc_ui_setup_windows(void);

void
sircc_ui_initialize(void) {
    int height;

    initscr();
    keypad(stdscr, 1);
    nonl();
    cbreak();
    noecho();

    start_color();
    init_pair(0, 0, 0);
    init_pair(1, 1, 0);
    init_pair(2, 2, 0);
    init_pair(3, 3, 0);
    init_pair(4, 4, 0);
    init_pair(5, 5, 0);
    init_pair(6, 6, 0);
    init_pair(7, 7, 0);

    clear();
    refresh();

    height = getmaxy(stdscr);
    if (height < 8)
        die("terminal too small, not enough lines");

    sircc_ui_setup_windows();

    sircc_ui_topic_redraw();
    sircc_ui_main_redraw();
    sircc_ui_chans_redraw();
    sircc_ui_servers_redraw();
    sircc_ui_prompt_redraw();

    sircc_ui_update();

    sircc.ui_setup = true;
}

void
sircc_ui_shutdown(void) {
    delwin(sircc.win_topic);
    delwin(sircc.win_main);
    delwin(sircc.win_servers);
    delwin(sircc.win_chans);
    delwin(sircc.win_prompt);

    endwin();

    sircc.ui_setup = false;
}

void
sircc_ui_on_resize(void) {
    struct winsize size;

    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &size) == -1)
        die("cannot get terminal size: %m");

    if (size.ws_row < 8)
        die("terminal too small, not enough lines");

    resizeterm(size.ws_row, size.ws_col);

    sircc_ui_setup_windows();

    for (size_t i = 0; i < sircc.nb_servers; i++) {
        struct sircc_server *server;
        struct sircc_chan *chan;

        server = sircc.servers[i];

        server->history.layout.dirty = true;

        chan = server->chans;
        while (chan) {
            chan->history.layout.dirty = true;
            chan = chan->next;
        }
    }

    sircc_ui_topic_redraw();
    sircc_ui_main_redraw();
    sircc_ui_chans_redraw();
    sircc_ui_servers_redraw();
    sircc_ui_prompt_redraw();

    sircc_ui_update();
}

void
sircc_ui_update(void) {
    /* Ncurses moves the physical cursor when refreshing a window; we want to
     * keep the cursor in the prompt window all the time. */
    wnoutrefresh(sircc.win_prompt);

    doupdate();
}

void
sircc_ui_topic_redraw(void) {
    struct sircc_server *server;
    struct sircc_chan *chan;
    WINDOW *win;

    win = sircc.win_topic;

    server = sircc_server_get_current();
    chan = server->current_chan;

    wmove(win, 0, 0);
    wclrtoeol(win);
    wbkgd(win, A_REVERSE);

    if (chan && chan->topic)
        waddstr(win, chan->topic);

    wnoutrefresh(win);
}

void
sircc_ui_main_redraw(void) {
    struct sircc_server *server;
    struct sircc_chan *chan;
    struct sircc_history *history;
    struct sircc_layout *layout;
    size_t margin_sz = 0;
    size_t nb_rows;
    WINDOW *win;
    int win_height;
    int y;

    win = sircc.win_main;

    server = sircc_server_get_current();
    chan = server->current_chan;
    if (chan) {
        history = &chan->history;
    } else {
        history = &server->history;
    }

    layout = &history->layout;
    if (layout->dirty)
        sircc_history_recompute_layout(history);

    wmove(win, 0, 0);
    werase(win);

    y = 0;

    margin_sz = sircc_history_margin_size(history);

    win_height = getmaxy(win);
    if (layout->nb_rows > (size_t)win_height) {
        nb_rows = (size_t)win_height;
    } else {
        nb_rows = layout->nb_rows;
    }

    for (size_t i = layout->start_idx + layout->nb_rows - nb_rows;
         i < layout->start_idx + layout->nb_rows; i++) {
        const struct sircc_layout_row *row;
        const struct sircc_history_entry *entry;
        int attrs;

        row = layout->rows + i;
        entry = row->entry;

        switch (entry->type) {
        case SIRCC_HISTORY_CHAN_MSG:
            attrs = 0;
            break;

        case SIRCC_HISTORY_SERVER_MSG:
            attrs = COLOR_PAIR(4);
            break;

        case SIRCC_HISTORY_TRACE:
            attrs = COLOR_PAIR(8) | A_BOLD;
            break;

        case SIRCC_HISTORY_INFO:
            attrs = COLOR_PAIR(2);
            break;

        case SIRCC_HISTORY_ERROR:
            attrs = COLOR_PAIR(1);
            break;
        }

        if (row->is_entry_first_row) {
            wmove(win, y, 0);
            sircc_ui_write(win, entry->margin_text, strlen(entry->margin_text));

            wattron(win, attrs);
            sircc_ui_write(win, row->text, row->text_sz);
            wattroff(win, attrs);
        } else {
            wmove(win, y, margin_sz);

            wattron(win, attrs);
            waddnstr(win, row->text, row->text_sz);
            wattroff(win, attrs);
        }

        y++;
    }

    wnoutrefresh(win);
}

void
sircc_ui_chans_redraw(void) {
    struct sircc_server *server;
    struct sircc_chan *chan;
    WINDOW *win;

    win = sircc.win_chans;

    wmove(win, 0, 0);
    wclrtoeol(win);
    wbkgd(win, A_REVERSE);

    server = sircc_server_get_current();

    if (!server->current_chan)
        wattron(win, A_BOLD);

    waddstr(win, server->name);

    if (!server->current_chan)
        wattroff(win, A_BOLD);

    chan = server->chans;
    while (chan) {
        bool is_current;

        is_current = sircc_chan_is_current(chan);

        waddch(win, ' ');

        if (is_current)
            wattron(win, A_BOLD);

        waddstr(win, chan->name);

        if (is_current)
            wattroff(win, A_BOLD);

        chan = chan->next;
    }

    wnoutrefresh(win);
}

void
sircc_ui_servers_redraw(void) {
    WINDOW *win;

    win = sircc.win_servers;

    wmove(win, 0, 0);
    wclrtoeol(win);
    wbkgd(win, A_REVERSE);

    for (size_t i = 0; i < sircc.nb_servers; i++) {
        struct sircc_server *server;
        bool is_current;

        server = sircc.servers[i];
        is_current = sircc_server_is_current(server);

        if (i > 0)
            waddch(win, ' ');

        if (is_current)
            wattron(win, A_BOLD);

        waddstr(win, server->name);

        if (is_current)
            wattroff(win, A_BOLD);
    }

    wnoutrefresh(win);
}

void
sircc_ui_prompt_redraw(void) {
    static const char prefix[] = "> ";
    static size_t prefix_len = sizeof(prefix) - 1;

    WINDOW *win;
    const char *prompt, *str;
    size_t prompt_len, nb_bytes, offset, width;

    win = sircc.win_prompt;
    width = (size_t)(getmaxx(win) - 1); /* space for the cursor */

    wmove(win, 0, 0);
    wclrtoeol(win);

    wattron(win, A_BOLD);
    waddstr(win, prefix);
    width -= prefix_len;
    wattroff(win, A_BOLD);

    prompt = sircc_buf_data(&sircc.prompt_buf);
    prompt_len = sircc_buf_length(&sircc.prompt_buf);
    if (prompt_len == 0)
        goto end;

    str = prompt;
    nb_bytes = prompt_len;

    if (sircc.prompt_cursor >= width) {
        str += sircc.prompt_cursor - width;
        nb_bytes = prompt_len - (size_t)(str - prompt);
    }

    waddnstr(win, str, nb_bytes);

    offset = (size_t)(str - prompt);
    wmove(win, 0, (int)(prefix_len + sircc.prompt_vcursor - offset));

end:
    wnoutrefresh(win);
    refresh();
}

int
sircc_ui_main_window_width(void) {
    return getmaxx(sircc.win_main);
}

void
sircc_ui_server_select(int idx) {
    assert(idx >= 0 && (size_t)idx < sircc.nb_servers);

    sircc.current_server = idx;

    sircc_ui_topic_redraw();
    sircc_ui_main_redraw();
    sircc_ui_servers_redraw();
    sircc_ui_chans_redraw();

    sircc_ui_update();
}

void
sircc_ui_server_select_previous(void) {
    int idx;

    idx = sircc.current_server - 1;
    if (idx < 0)
        idx = sircc.nb_servers - 1;

    sircc_ui_server_select(idx);
}

void
sircc_ui_server_select_next(void) {
    int idx;

    idx = sircc.current_server + 1;
    if ((size_t)idx >= sircc.nb_servers)
        idx = 0;

    sircc_ui_server_select(idx);
}

void
sircc_ui_server_select_chan(struct sircc_server *server,
                            struct sircc_chan *chan) {
    server->last_chan = server->current_chan;
    server->current_chan = chan;

    sircc_ui_topic_redraw();
    sircc_ui_main_redraw();
    sircc_ui_chans_redraw();

    sircc_ui_update();
}

void
sircc_ui_server_select_previous_chan(struct sircc_server *server) {
    struct sircc_chan *chan;

    if (!server->chans)
        return;

    if (server->current_chan) {
        chan = server->current_chan->prev;
    } else {
        chan = server->chans;
        while (chan->next)
            chan = chan->next;
    }

    sircc_ui_server_select_chan(server, chan);
}

void
sircc_ui_server_select_next_chan(struct sircc_server *server) {
    struct sircc_chan *chan;

    if (!server->chans)
        return;

    if (server->current_chan) {
        chan = server->current_chan->next;
    } else {
        chan = server->chans;
    }

    sircc_ui_server_select_chan(server, chan);
}

void
sircc_ui_prompt_add(const char *str) {
    size_t len;

    len = strlen(str);
    sircc_buf_insert(&sircc.prompt_buf, sircc.prompt_cursor, str, len);

    sircc.prompt_cursor += len;
    sircc.prompt_vcursor += sircc_utf8_nb_chars(str);

    sircc_ui_completion_reset();

    sircc_ui_prompt_redraw();
    sircc_ui_update();
}

void
sircc_ui_prompt_delete_previous_char(void) {
    char *ptr, *prompt;
    size_t len, nb_bytes = 0, nb_deleted;

    if (sircc.prompt_cursor == 0)
        return;

    prompt = sircc_buf_data(&sircc.prompt_buf);
    len = sircc_buf_length(&sircc.prompt_buf);
    if (len == 0)
        return;

    ptr = prompt + sircc.prompt_cursor;
    nb_bytes = 0;

    do {
        ptr--;
        nb_bytes++;
    } while (ptr > prompt && sircc_utf8_is_continuation_byte(*ptr));

    nb_deleted = sircc_buf_remove_at(&sircc.prompt_buf, sircc.prompt_cursor,
                                     nb_bytes);

    sircc.prompt_cursor -= nb_deleted;
    sircc.prompt_vcursor--;

    sircc_ui_completion_reset();

    sircc_ui_prompt_redraw();
    sircc_ui_update();
}

void
sircc_ui_prompt_delete_from_cursor(void) {
    sircc_buf_truncate(&sircc.prompt_buf, sircc.prompt_cursor);

    sircc_ui_prompt_redraw();
    sircc_ui_update();
}

void
sircc_ui_prompt_move_cursor_backward(void) {
    char *ptr;
    size_t len;

    ptr = sircc_buf_data(&sircc.prompt_buf);
    len = sircc_buf_length(&sircc.prompt_buf);

    if (sircc.prompt_cursor == 0)
        return;

    do {
        sircc.prompt_cursor--;
        if (sircc_utf8_is_leading_byte(ptr[sircc.prompt_cursor]))
            break;
    } while (sircc.prompt_cursor > 0);

    sircc.prompt_vcursor--;

    sircc_ui_prompt_redraw();
    sircc_ui_update();
}

void
sircc_ui_prompt_move_cursor_forward(void) {
    char *ptr;
    size_t len;

    ptr = sircc_buf_data(&sircc.prompt_buf);
    len = sircc_buf_length(&sircc.prompt_buf);

    if (sircc.prompt_cursor >= len)
        return;

    do {
        sircc.prompt_cursor++;
        if (sircc_utf8_is_leading_byte(ptr[sircc.prompt_cursor]))
            break;
    } while (sircc.prompt_cursor <= len);

    sircc.prompt_vcursor++;

    sircc_ui_prompt_redraw();
    sircc_ui_update();
}

void
sircc_ui_prompt_move_cursor_beginning(void) {
    sircc.prompt_cursor = 0;
    sircc.prompt_vcursor = 0;

    sircc_ui_prompt_redraw();
    sircc_ui_update();
}

void
sircc_ui_prompt_move_cursor_end(void) {
    size_t len, nb_chars;

    len = sircc_buf_length(&sircc.prompt_buf);
    nb_chars = sircc_buf_utf8_nb_chars(&sircc.prompt_buf);

    sircc.prompt_cursor = len;
    sircc.prompt_vcursor = nb_chars;

    sircc_ui_prompt_redraw();
    sircc_ui_update();
}

void
sircc_ui_prompt_clear(void) {
    sircc_buf_clear(&sircc.prompt_buf);

    sircc.prompt_cursor = 0;
    sircc.prompt_vcursor = 0;

    sircc_ui_completion_reset();

    sircc_ui_prompt_redraw();
    sircc_ui_update();
}

void
sircc_ui_prompt_execute(void) {
    struct sircc_server *server;
    struct sircc_chan *chan;
    bool is_cmd;

    if (sircc_buf_length(&sircc.prompt_buf) == 0)
        return;

    is_cmd = sircc_buf_data(&sircc.prompt_buf)[0] == '/';

    server = sircc_server_get_current();
    chan = server->current_chan;
    if (chan || is_cmd) {
        if (is_cmd) {
            struct sircc_cmd cmd;
            int ret;

            ret = sircc_cmd_parse(&cmd, &sircc.prompt_buf);
            if (ret == -1) {
                sircc_chan_log_error(NULL, "cannot parse command: %s",
                                     sircc_get_error());
            } else if (ret == 0) {
                sircc_chan_log_error(NULL, "cannot parse command:"
                                     " truncated input");
            } else {
                sircc_cmd_run(&cmd);
                sircc_cmd_free(&cmd);
            }
        } else {
            char *text;

            text = sircc_buf_dup_str(&sircc.prompt_buf);

            sircc_server_send_privmsg(server, chan->name, text);
            sircc_chan_add_msg(chan, server->current_nickname, text);

            sircc_free(text);
        }
    } else {
        sircc_server_write(server, sircc_buf_data(&sircc.prompt_buf),
                           sircc_buf_length(&sircc.prompt_buf));
        sircc_server_write(server, "\r\n", 2);
    }

    sircc_ui_prompt_clear();
}

int
sircc_ui_write(WINDOW *win, const char *str, size_t sz) {
    /*
     * ^a0   reset attributes
     * ^a1   bold
     * ^a7   reverse
     *
     * ^c0  black foreground
     * ^c1  red foreground
     * ^c2  green foreground
     * ^c3  yellow foreground
     * ^c4  blue foreground
     * ^c5  magenta foreground
     * ^c6  cyan foreground
     * ^c7  white foreground
     * ^c9  default foreground
     *
     * ^^   '^' character
     */

    const char *ptr;
    size_t len;

    ptr = str;
    len = sz;

    while (len > 0) {
        if (*ptr == '^') {
            ptr++;
            len--;
            if (len == 0) {
                sircc_set_error("truncated sequence");
                goto error;
            }

            if (*ptr == '^') {
                waddch(win, (chtype)*ptr);
                ptr++;
                len--;
            } else if (*ptr == 'a') {
                char digit;

                ptr++;
                len--;
                if (len == 0) {
                    sircc_set_error("truncated attribute sequence");
                    goto error;
                }

                digit = *ptr - '0';

                switch (digit) {
                case 0:
                    wattrset(win, A_NORMAL);
                    break;

                case 1:
                    wattron(win, A_BOLD);
                    break;

                case 7:
                    wattron(win, A_REVERSE);
                    break;
                }

                ptr++;
                len--;
            } else if (*ptr == 'c') {
                char digit;

                ptr++;
                len--;
                if (len == 0) {
                    sircc_set_error("truncated color sequence");
                    goto error;
                }

                digit = *ptr - '0';

                wattron(win, COLOR_PAIR(digit));

                ptr++;
                len--;
            }
        } else {
            waddch(win, (chtype)*ptr);
            ptr++;
            len--;
        }
    }

    wattrset(win, A_NORMAL);
    return 0;

error:
    wattrset(win, A_NORMAL);
    return -1;
}

int
sircc_ui_vprintf(WINDOW *win, const char *fmt, va_list ap) {
    struct sircc_buf buf;
    const char *ptr;
    size_t len;

    sircc_buf_init(&buf);
    if (sircc_buf_add_vprintf(&buf, fmt, ap) == -1)
        goto error;

    ptr = sircc_buf_data(&buf);
    len = sircc_buf_length(&buf);

    if (sircc_ui_write(win, ptr, len) == -1)
        goto error;

    sircc_buf_free(&buf);
    return 0;

error:
    sircc_buf_free(&buf);
    return -1;
}

int
sircc_ui_printf(WINDOW *win, const char *fmt, ...) {
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = sircc_ui_vprintf(win, fmt, ap);
    va_end(ap);

    return ret;
}

void
sircc_ui_completion_reset(void) {
    sircc_free(sircc.completion_prefix);
    sircc.completion_prefix = NULL;

    sircc_free(sircc.last_completion);
    sircc.last_completion = NULL;

    sircc.completion_offset = 0;

    sircc.completion = false;
}

void
sircc_ui_completion_next(void) {
    struct sircc_server *server;
    struct sircc_chan *chan;
    size_t offset;

    char *completion;
    const char *suffix;
    const char *ptr;
    size_t len;

    bool is_command;

    server = sircc_server_get_current();
    chan = server->current_chan;

    if (!sircc.completion) {
        sircc.completion_prefix = sircc_ui_completion_prefix(&offset);
        if (!sircc.completion_prefix) {
            sircc_ui_completion_reset();
            return;
        }

        sircc.completion_offset = offset;
    }

    ptr = sircc_buf_data(&sircc.prompt_buf);
    len = sircc_buf_length(&sircc.prompt_buf);

    /* Search for a matching user/command */
    is_command = (sircc.completion_prefix[0] == '/');

    if (is_command) {
        completion = sircc_cmd_next_completion(sircc.completion_prefix,
                                               sircc.last_completion);
        suffix = " ";
    } else if (chan) {
        completion = sircc_chan_next_user_completion(chan,
                                                     sircc.completion_prefix,
                                                     sircc.last_completion);
        if (sircc.completion_offset == 0) {
            suffix = ": ";
        } else {
            suffix = " ";
        }
    } else {
        sircc.completion = false;
        return;
    }

    if (!completion) {
        sircc_free(completion);
        sircc_ui_completion_reset();
        return;
    }

    sircc_ui_completion_update_prompt(completion, suffix);

    sircc_free(sircc.last_completion);
    sircc.last_completion = completion;

    sircc.completion = true;
}

void
sircc_ui_completion_update_prompt(const char *completion, const char *suffix) {
    size_t len;

    len = sircc_buf_length(&sircc.prompt_buf) -  sircc.completion_offset;

    sircc_buf_remove(&sircc.prompt_buf, len);
    sircc_buf_add(&sircc.prompt_buf, completion, strlen(completion));
    sircc_buf_add(&sircc.prompt_buf, suffix, strlen(suffix));

    sircc_ui_prompt_redraw();
    sircc_ui_update();
}

static char *
sircc_ui_completion_prefix(size_t *poffset) {
    const char *ptr;
    size_t len, offset;

    ptr = sircc_buf_data(&sircc.prompt_buf);
    len = sircc_buf_length(&sircc.prompt_buf);
    if (len == 0)
        return NULL;

    offset = len - 1;
    if (isspace(ptr[offset]))
        return NULL;

    /* Find the last beginning of a word */
    while (offset > 0) {
        if (isspace(ptr[offset])) {
            offset++;
            *poffset = offset;
            return sircc_strndup(ptr + offset, len - offset);
        }

        offset--;
    }

    /* The prefix is the whole prompt */
    *poffset = 0;
    return sircc_strndup(ptr, len);
}

static void
sircc_ui_setup_windows(void) {
    int width, height;

    getmaxyx(stdscr, height, width);

    if (sircc.win_topic)
        delwin(sircc.win_topic);
    sircc.win_topic = subwin(stdscr, 1, width, 0, 0);

    if (sircc.win_main)
        delwin(sircc.win_main);
    sircc.win_main = subwin(stdscr, height - 4, width, 1, 0);

    if (sircc.win_servers)
        delwin(sircc.win_servers);
    sircc.win_servers = subwin(stdscr, 1, width, height - 2, 0);

    if (sircc.win_chans)
        delwin(sircc.win_chans);
    sircc.win_chans = subwin(stdscr, 1, width, height - 3, 0);

    if (sircc.win_prompt)
        delwin(sircc.win_prompt);
    sircc.win_prompt = subwin(stdscr, 1, width, height - 1, 0);
}
