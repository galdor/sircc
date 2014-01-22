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

static struct {
    const char *name;
    const char *sequence;
} sircc_highlighting_sequences[] = {
    {"black",     "^c0"},
    {"red",       "^c1"},
    {"green",     "^c2"},
    {"yellow",    "^c3"},
    {"blue",      "^c4"},
    {"magenta",   "^c5"},
    {"cyan",      "^c6"},
    {"white",     "^c7"},
    {"gray",      "^c8"},
    {"default",   "^c9"},

    {"bold",      "^a1"},
    {"underline", "^a4"},
    {"reverse",   "^a7"},
};

static void sircc_process_buf(struct sircc_buf *, bool);

static void sircc_escape_format_sequences(struct sircc_buf *);

static void sircc_highlighter_free(struct sircc_highlighter *);
static int sircc_highlighter_init_escape_sequences(struct sircc_highlighter *,
                                                   const char *, size_t);

static pcre *sircc_pcre_compile(const char *, pcre_extra **);

int
sircc_processing_initialize(void) {
    const char **strings;
    size_t nb_strings;

    strings = sircc_cfg_strings(&sircc.cfg, "highlight", &nb_strings);
    if (!strings)
        return 0;

    sircc.nb_highlighters = nb_strings;
    sircc.highlighters = sircc_calloc(nb_strings,
                                      sizeof(struct sircc_highlighter));

    for (size_t i = 0; i < nb_strings; i++) {
        struct sircc_highlighter *highlighter;
        const char *string, *space;
        const char *regexp_str;
        size_t sz;

        highlighter = &sircc.highlighters[i];
        string = strings[i];

        space = strchr(string, ' ');
        if (!space) {
            sircc_set_error("missing regexp");
            goto error;
        }

        /* Build the prefix/suffix escape sequence strings */
        sz = (size_t)(space - string);
        if (sircc_highlighter_init_escape_sequences(highlighter,
                                                    string, sz) == -1) {
            goto error;
        }

        /* Compile the regexp */
        regexp_str = space + 1;
        if (*regexp_str == '\0') {
            sircc_set_error("empty regexp");
            goto error;
        }

        highlighter->regexp = sircc_pcre_compile(regexp_str,
                                                 &highlighter->regexp_extra);
    }

    return 0;

error:
    sircc_processing_shutdown();
    return -1;
}

void
sircc_processing_shutdown(void) {
    for (size_t i = 0; i < sircc.nb_highlighters; i++)
        sircc_highlighter_free(&sircc.highlighters[i]);
}

char *
sircc_process_text(const char *str, bool minimal) {
    struct sircc_buf buf;
    char *nstr;

    sircc_buf_init(&buf);
    sircc_buf_add(&buf, str, strlen(str));

    sircc_process_buf(&buf, minimal);
    nstr = sircc_buf_dup_str(&buf);

    sircc_buf_free(&buf);
    return nstr;
}

static void
sircc_process_buf(struct sircc_buf *buf, bool minimal) {
    const char *suffix;
    size_t suffix_len;

    suffix = "^a0";
    suffix_len = strlen(suffix);

    sircc_escape_format_sequences(buf);

    if (minimal)
        return;

    for (size_t i = 0; i < sircc.nb_highlighters; i++) {
        struct sircc_highlighter *highlighter;
        size_t sequence_len;
        size_t offset;
        int substrings[3];
        int ret;

        highlighter = &sircc.highlighters[i];

        sequence_len = strlen(highlighter->sequence);
        offset = 0;

        while (offset < sircc_buf_length(buf)) {
            const char *buf_ptr;
            size_t match_offset, match_len;

            buf_ptr = sircc_buf_data(buf);

            ret = pcre_exec(highlighter->regexp, highlighter->regexp_extra,
                            buf_ptr, sircc_buf_length(buf), offset, 0,
                            substrings, 3);
            if (ret <= 0) {
                if (ret != PCRE_ERROR_NOMATCH) {
                    sircc_chan_log_error(NULL, "cannot execute regexp (%d)",
                                         ret);
                }

                break;
            }

            match_offset = (size_t)substrings[0];
            match_len = (size_t)(substrings[1] - substrings[0]);

            offset = match_offset;

            sircc_buf_insert(buf, offset, highlighter->sequence, sequence_len);
            offset += sequence_len;

            offset += match_len;
            sircc_buf_insert(buf, offset, suffix, suffix_len);
            offset += suffix_len;
        }
    }
}

static void
sircc_escape_format_sequences(struct sircc_buf *buf) {
    size_t offset;

    offset = 0;
    for (;;) {
        char *ptr;
        size_t len;

        ptr = sircc_buf_data(buf);
        len = sircc_buf_length(buf);

        if (offset >= len)
            break;

        if (ptr[offset] == '^') {
            sircc_buf_insert(buf, offset, "^", 1);
            offset++;
        }

        offset++;
    }
}

static void
sircc_highlighter_free(struct sircc_highlighter *highlighter) {
    pcre_free(highlighter->regexp);
    pcre_free_study(highlighter->regexp_extra);

    sircc_free(highlighter->sequence);
}

static int
sircc_highlighter_init_escape_sequences(struct sircc_highlighter *highlighter,
                                        const char *str, size_t sz) {
    const char *and;
    const char *ptr;
    size_t len;
    size_t nb_sequences;

    nb_sequences = sizeof(sircc_highlighting_sequences)
                 / sizeof(sircc_highlighting_sequences[0]);

    ptr = str;
    len = sz;

    while (len > 0) {
        const char *sequence;
        size_t toklen;

        and = memchr(ptr, '&', len);
        if (and) {
            toklen = (size_t)(and - ptr);
        } else {
            toklen = len;
        }

        sequence = NULL;
        for (size_t i = 0; i < nb_sequences; i++) {
            const char *name;

            name = sircc_highlighting_sequences[i].name;

            if (toklen == strlen(name) && memcmp(ptr, name, toklen) == 0) {
                sequence = sircc_highlighting_sequences[i].sequence;
                break;
            }
        }

        if (!sequence) {
            char tmp[toklen + 1];

            strlcpy(tmp, ptr, toklen + 1);
            sircc_set_error("unknown display attribute '%s'", tmp);
            return -1;
        }

        if (highlighter->sequence) {
            char *tmp;

            sircc_asprintf(&tmp, "%s%s", highlighter->sequence, sequence);
            sircc_free(highlighter->sequence);
            highlighter->sequence = tmp;
        } else {
            highlighter->sequence = strdup(sequence);
        }

        ptr += toklen;
        len -= toklen;

        if (and) {
            ptr++;
            len--;
        }
    }

    return 0;
}

static pcre *
sircc_pcre_compile(const char *str, pcre_extra **pextra) {
    const char *error_str;
    int error_offset;
    pcre *regexp;

    regexp = pcre_compile(str, 0, &error_str, &error_offset, NULL);
    if (!regexp) {
        sircc_set_error("cannot compile regex: %s", error_str);
        return NULL;
    }

    *pextra = pcre_study(regexp, PCRE_STUDY_JIT_COMPILE, &error_str);
    if (!*pextra) {
        sircc_set_error("cannot study regex: %s", error_str);
        pcre_free(regexp);
        return NULL;
    }

    return regexp;
}
