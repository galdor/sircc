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
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "sircc.h"

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
            waddstr(win, entry->margin_text);

            wattron(win, attrs);
            waddnstr(win, row->text, row->text_sz);
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

    waddstr(win, server->host);

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
    WINDOW *win;
    char *str, *utf8_str;
    size_t len, nb_bytes;

    win = sircc.win_prompt;

    wmove(win, 0, 0);
    wclrtoeol(win);

    wattron(win, A_BOLD);
    waddstr(win, "> ");
    wattroff(win, A_BOLD);

    len = sircc_buf_length(&sircc.prompt_buf);
    str = sircc_buf_data(&sircc.prompt_buf);
    if (str) {
        utf8_str = sircc_str_to_utf8(str, len, &nb_bytes);
        if (utf8_str) {
            waddnstr(win, str, nb_bytes);
            sircc_free(utf8_str);
        } else {
            sircc_server_log_error(NULL, "%s", sircc_get_error());
        }
    }

    wnoutrefresh(win);
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
sircc_ui_prompt_delete_previous_char(void) {
    char *prompt, *utf8_prompt = NULL;
    const char *ptr;
    size_t len, sz = 0;

    /* XXX overkill */

    if (sircc_buf_length(&sircc.prompt_buf) == 0)
        return;

    prompt = sircc_buf_data(&sircc.prompt_buf);
    len = sircc_buf_length(&sircc.prompt_buf);

    utf8_prompt = sircc_str_to_utf8(prompt, len, NULL);
    if (!utf8_prompt) {
        sircc_server_log_error(NULL, "%s", sircc_get_error());
        goto error;
    }

    len = strlen(utf8_prompt);
    if (len == 0)
        return;

    ptr = utf8_prompt + len - 1;
    for (;;) {
        if ((*ptr & 0xc0) == 0x80) {
            /* UTF-8 continuation byte */
            if (ptr == utf8_prompt) {
                /* The first byte cannot be a continuation */
                sircc_server_log_error(NULL,
                                       "invalid first byte in UTF-8 string");
                goto error;
            }

            ptr--;
            sz++;
        } else {
            sz++;
            break;
        }
    }

    sircc_free(utf8_prompt);

    sircc_buf_remove(&sircc.prompt_buf, sz);

    sircc_ui_prompt_redraw();
    sircc_ui_update();
    return;

error:
    sircc_free(utf8_prompt);
    sircc_ui_prompt_clear();
}

void
sircc_ui_prompt_clear(void) {
    sircc_buf_clear(&sircc.prompt_buf);

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
            sircc_chan_add_msg(chan, server->nickname, text);

            sircc_free(text);
        }
    } else {
        sircc_server_write(server, sircc_buf_data(&sircc.prompt_buf),
                           sircc_buf_length(&sircc.prompt_buf));
        sircc_server_write(server, "\r\n", 2);
    }

    sircc_ui_prompt_clear();
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
