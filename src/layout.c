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

#include "sircc.h"

static void sircc_layout_row_init(struct sircc_layout_row *);

void
sircc_layout_init(struct sircc_layout *layout) {
    memset(layout, 0, sizeof(struct sircc_layout));
}

void
sircc_layout_free(struct sircc_layout *layout) {
    if (!layout)
        return;

    sircc_free(layout->rows);
}

void
sircc_layout_add_row(struct sircc_layout *layout,
                     const struct sircc_layout_row *row) {
    if (!layout->rows) {
        layout->rows_sz = 16;
        layout->nb_rows = 0;
        layout->rows = sircc_calloc(layout->rows_sz,
                                    sizeof(struct sircc_layout_row));
    } else if (layout->start_idx + layout->nb_rows + 1 >= layout->rows_sz) {
        if (layout->start_idx > 0) {
            size_t sz;

            /* Repack */

            sz = layout->nb_rows * sizeof(struct sircc_layout_row);
            memmove(layout->rows, layout->rows + layout->start_idx, sz);

            layout->start_idx = 0;
        } else {
            size_t sz;

            /* Resize */

            layout->rows_sz *= 2;

            sz = layout->rows_sz * sizeof(struct sircc_layout_row);
            layout->rows = sircc_realloc(layout->rows, sz);
            memset(layout->rows + layout->rows_sz / 2, 0, sz / 2);
        }
    }

    layout->rows[layout->start_idx + layout->nb_rows] = *row;
    layout->nb_rows++;
}

void
sircc_layout_add_history_entry(struct sircc_layout *layout,
                               struct sircc_history_entry *entry) {
    struct sircc_layout_row row;
    int window_width, margin_sz, width, x;
    const char *ptr, *start;

    window_width = (int)sircc_ui_main_window_width();
    margin_sz = (int)strlen(entry->margin_text);
    width = window_width - margin_sz;

    x = 0;

    ptr = entry->text;
    start = ptr;

    while (*ptr != '\0') {
        size_t nb_bytes;
        bool truncated_seq, eos;

        /* If we find a truncated UTF-8 sequence, we ignore it. It should not
         * happen since the string was converted to UTF-8 by iconv. */

        truncated_seq = false;

        if ((*ptr & 0x80) == 0x0) {
            nb_bytes = 1;
        } else if ((*ptr & 0xe0) == 0xc0) {
            nb_bytes = 2;

            if (*(ptr + 1) == '\0')
                truncated_seq = true;
        } else if ((*ptr & 0xf0) == 0xe0) {
            nb_bytes = 3;

            if (*(ptr + 1) == '\0' || *(ptr + 2) == '\0')
                truncated_seq = true;
        } else if ((*ptr & 0xf8) == 0xf0) {
            nb_bytes = 4;

            if (*(ptr + 1) == '\0' || *(ptr + 2) == '\0' || *(ptr + 3) == '\0')
                truncated_seq = true;
        } else {
            /* TODO Handle invalid UTF-8 sequences */
            nb_bytes = 1;
        }

        if (!truncated_seq) {
            ptr += nb_bytes;
            x++;
        }

        eos = truncated_seq || *ptr == '\0';

        if (x >= width || eos) {
            bool is_first_row;

            is_first_row = (start == entry->text);

            sircc_layout_row_init(&row);

            if (is_first_row)
                row.margin_text = entry->margin_text;
            row.text = start;
            row.text_sz = (size_t)(ptr - start);
            row.entry = entry;
            row.is_entry_first_row = is_first_row;

            sircc_layout_add_row(layout, &row);

            start = ptr;
            x = 0;
        }
    }
}

void
sircc_layout_skip_history_entry(struct sircc_layout *layout) {
    const struct sircc_history_entry *entry;
    size_t nb_rows_in_entry;

    /* Skip all rows of the oldest history entry */

    if (layout->nb_rows == 0)
        return;

    nb_rows_in_entry = 0;

    entry = layout->rows[layout->start_idx].entry;

    for (size_t i = layout->start_idx;
         i < layout->start_idx + layout->nb_rows; i++) {
        struct sircc_layout_row *row;

        row = &layout->rows[i];
        if (row->entry == entry) {
            nb_rows_in_entry++;
        } else {
            memset(layout->rows + layout->start_idx, 0,
                   nb_rows_in_entry * sizeof(struct sircc_layout_row));
            layout->start_idx = i;
            layout->nb_rows -= nb_rows_in_entry;
            return;
        }
    }
}

static void
sircc_layout_row_init(struct sircc_layout_row *row) {
    memset(row, 0, sizeof(struct sircc_layout_row));
}
