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

void
sircc_history_init(struct sircc_history *history, size_t sz) {
    memset(history, 0, sizeof(struct sircc_history));

    history->sz = sz;
    history->entries = sircc_calloc(sz, sizeof(struct sircc_history_entry));
}

void
sircc_history_free(struct sircc_history *history) {

    for (size_t i = 0; i < history->sz; i++) {
        struct sircc_history_entry *entry;

        entry = history->entries + i;
        sircc_free(entry->src);
        sircc_free(entry->text);
    }

    free(history->entries);
}

void
sircc_history_add_entry(struct sircc_history *history,
                        struct sircc_history_entry *entry) {
    struct sircc_history_entry *head;
    size_t idx;

    idx = (history->start_idx + history->nb_entries) % history->sz;
    head = history->entries + idx;

    if ((history->nb_entries + 1) >= history->sz) {
        /* We are overwriting the oldest entry */
        sircc_free(head->src);
        sircc_free(head->text);

        history->start_idx = (history->start_idx + 1) % history->sz;
    }

    *head = *entry;

    if (history->nb_entries < history->sz)
        history->nb_entries++;
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
