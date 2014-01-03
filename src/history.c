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

#include <string.h>
#include <time.h>

#include "sircc.h"

static void sircc_history_entry_free(struct sircc_history_entry *);
static void sircc_history_entry_update_margin_text(struct sircc_history_entry *);

void
sircc_history_init(struct sircc_history *history, size_t sz) {
    memset(history, 0, sizeof(struct sircc_history));

    history->sz = sz;
    history->entries = sircc_calloc(sz, sizeof(struct sircc_history_entry));

    sircc_layout_init(&history->layout);
}

void
sircc_history_free(struct sircc_history *history) {

    for (size_t i = 0; i < history->sz; i++)
        sircc_history_entry_free(history->entries + i);

    sircc_layout_free(&history->layout);

    free(history->entries);
}

void
sircc_history_add_entry(struct sircc_history *history,
                        const struct sircc_history_entry *entry) {
    struct sircc_history_entry *head;
    size_t idx;

    idx = (history->start_idx + history->nb_entries) % history->sz;
    head = history->entries + idx;

    if ((history->nb_entries + 1) >= history->sz) {
        /* We are overwriting the oldest entry */
        sircc_layout_skip_history_entry(&history->layout);
        sircc_history_entry_free(head);

        history->start_idx = (history->start_idx + 1) % history->sz;
    }

    *head = *entry;

    if (history->nb_entries < history->sz)
        history->nb_entries++;

    sircc_history_entry_update_margin_text(head);
    sircc_layout_add_history_entry(&history->layout, head);
}

void
sircc_history_add_chan_msg(struct sircc_history *history,
                           char *src, char *text) {
    struct sircc_history_entry entry;

    entry.type = SIRCC_HISTORY_CHAN_MSG;
    entry.date = time(NULL);
    entry.src = src;
    entry.text = text;

    sircc_history_add_entry(history, &entry);
}

void
sircc_history_add_server_msg(struct sircc_history *history, char *text) {
    struct sircc_history_entry entry;

    memset(&entry, 0, sizeof(struct sircc_history_entry));

    entry.type = SIRCC_HISTORY_SERVER_MSG;
    entry.date = time(NULL);
    entry.text = text;

    sircc_history_add_entry(history, &entry);
}

void
sircc_history_add_trace(struct sircc_history *history, char *text) {
    struct sircc_history_entry entry;

    memset(&entry, 0, sizeof(struct sircc_history_entry));

    entry.type = SIRCC_HISTORY_TRACE;
    entry.date = time(NULL);
    entry.text = text;

    sircc_history_add_entry(history, &entry);
}

void
sircc_history_add_info(struct sircc_history *history, char *text) {
    struct sircc_history_entry entry;

    memset(&entry, 0, sizeof(struct sircc_history_entry));

    entry.type = SIRCC_HISTORY_INFO;
    entry.date = time(NULL);
    entry.text = text;

    sircc_history_add_entry(history, &entry);
}

void
sircc_history_add_error(struct sircc_history *history, char *text) {
    struct sircc_history_entry entry;

    memset(&entry, 0, sizeof(struct sircc_history_entry));

    entry.type = SIRCC_HISTORY_ERROR;
    entry.date = time(NULL);
    entry.text = text;

    sircc_history_add_entry(history, &entry);
}

static void
sircc_history_entry_free(struct sircc_history_entry *entry) {
    if (!entry)
        return;

    sircc_free(entry->src);
    sircc_free(entry->margin_text);
    sircc_free(entry->text);
}

static void
sircc_history_entry_update_margin_text(struct sircc_history_entry *entry) {
    const char *date_fmt;
    int src_field_sz;

    char date_str[32];
    struct tm *tm;
    char *str;

    date_fmt = "%H:%M:%S";
    src_field_sz = 9;

    tm = localtime(&entry->date);
    strftime(date_str, sizeof(date_str), date_fmt, tm);

    switch (entry->type) {
    case SIRCC_HISTORY_CHAN_MSG:
        sircc_asprintf(&str, "%s %-*s  ", date_str, src_field_sz, entry->src);
        break;

    case SIRCC_HISTORY_SERVER_MSG:
    case SIRCC_HISTORY_TRACE:
    case SIRCC_HISTORY_INFO:
    case SIRCC_HISTORY_ERROR:
        sircc_asprintf(&str, "%s %-*s  ", date_str, src_field_sz, "");
        break;

    }

    if (entry->margin_text)
        sircc_free(entry->margin_text);
    entry->margin_text = str;
}
