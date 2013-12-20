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

#include <stdio.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "sircc.h"

static void sircc_ui_setup_windows(void);
static void sircc_ui_update(void);

static void sircc_ui_topic_redraw(void);
static void sircc_ui_main_redraw(void);
static void sircc_ui_chans_redraw(void);
static void sircc_ui_servers_redraw(void);
static void sircc_ui_prompt_redraw(void);

void
sircc_ui_initialize(void) {
    char term_dev[L_ctermid];
    int width, height;

    ctermid(term_dev);
    sircc.tty = open(term_dev, O_RDONLY);
    if (sircc.tty == -1)
        die("cannot open %s: %m", term_dev);

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

    getmaxyx(stdscr, height, width);
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

    if (sircc.tty >= 0) {
        close(sircc.tty);
        sircc.tty = -1;
    }

    sircc.ui_setup = false;
}

void
sircc_ui_on_resize(void) {
    struct winsize size;

    if (ioctl(sircc.tty, TIOCGWINSZ, &size) == -1)
        die("cannot get terminal size: %m");

    if (size.ws_row < 8)
        die("terminal too small, not enough lines");

    resizeterm(size.ws_row, size.ws_col);

    sircc_ui_setup_windows();

    sircc_ui_topic_redraw();
    sircc_ui_main_redraw();
    sircc_ui_chans_redraw();
    sircc_ui_servers_redraw();
    sircc_ui_prompt_redraw();

    sircc_ui_update();
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
    sircc.win_servers = subwin(stdscr, 1, width, height - 3, 0);

    if (sircc.win_chans)
        delwin(sircc.win_chans);
    sircc.win_chans = subwin(stdscr, 1, width, height - 2, 0);

    if (sircc.win_prompt)
        delwin(sircc.win_prompt);
    sircc.win_prompt = subwin(stdscr, 1, width, height - 1, 0);
}

static void
sircc_ui_update(void) {
    doupdate();
}

static void
sircc_ui_topic_redraw(void) {
    WINDOW *win;

    win = sircc.win_topic;

    wmove(win, 0, 0);
    waddstr(win, "topic");

    wnoutrefresh(win);
}

static void
sircc_ui_main_redraw(void) {
    WINDOW *win;

    win = sircc.win_main;

    wmove(win, 0, 0);
    waddstr(win, "main");

    wnoutrefresh(win);
}

static void
sircc_ui_chans_redraw(void) {
    WINDOW *win;

    win = sircc.win_chans;

    wmove(win, 0, 0);
    waddstr(win, "chans");

    wnoutrefresh(win);
}

static void
sircc_ui_servers_redraw(void) {
    WINDOW *win;

    win = sircc.win_servers;

    wmove(win, 0, 0);
    waddstr(win, "servers");

    wnoutrefresh(win);
}

static void
sircc_ui_prompt_redraw(void) {
    WINDOW *win;

    win = sircc.win_prompt;

    wmove(win, 0, 0);
    waddstr(win, "prompt");

    wnoutrefresh(win);
}
