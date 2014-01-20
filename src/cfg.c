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
#include <errno.h>
#include <limits.h>

#include <dirent.h>

#include "sircc.h"

#define SIRCC_CFG_KEY_MAXSZ 128

static void sircc_cfg_add_server(struct sircc_cfg *, const char *);

static int sircc_cfg_get_key_type(const char *, enum sircc_cfg_entry_type *);

static int sircc_cfg_entry_parse(struct sircc_cfg_entry **, const char *,
                                 char **);
static int sircc_cfg_entry_parse_value(struct sircc_cfg_entry *, const char *);
static void sircc_cfg_entry_add_string(struct sircc_cfg_entry *, const char *);
static void sircc_cfg_entry_delete(struct sircc_cfg_entry *);

static int sircc_cfg_parse_key_value(const char *, char **, char **);


static struct {
    const char *key;
    enum sircc_cfg_entry_type type;
} sircc_cfg_type_array[] = {
    /* Main */
    {"highlight",                         SIRCC_CFG_STRING_LIST},

    /* Servers */
    {"autoconnect",                       SIRCC_CFG_BOOLEAN},

    {"host",                              SIRCC_CFG_STRING},
    {"port",                              SIRCC_CFG_STRING},

    {"ssl",                               SIRCC_CFG_BOOLEAN},
    {"ssl_verify_certificate",            SIRCC_CFG_BOOLEAN},
    {"ssl_ca_certificate",                SIRCC_CFG_STRING},
    {"ssl_allow_self_signed_certificate", SIRCC_CFG_BOOLEAN},

    {"nickname",                          SIRCC_CFG_STRING},
    {"realname",                          SIRCC_CFG_STRING},
    {"max_nickname_length",               SIRCC_CFG_INTEGER},

    {"password",                          SIRCC_CFG_STRING},

    {"auto_command",                      SIRCC_CFG_STRING_LIST},

    /* Channels */
    {"autojoin",                          SIRCC_CFG_BOOLEAN},
};

static struct ht_table *sircc_cfg_types;


int
sircc_cfg_initialize(const char *dirpath) {
    size_t nb_types;

    sircc.cfgdir = dirpath;

    sircc_cfg_types = ht_table_new(ht_hash_string, ht_equal_string);

    nb_types = sizeof(sircc_cfg_type_array) / sizeof(sircc_cfg_type_array[0]);
    for (size_t i = 0; i < nb_types; i++) {
        ht_table_insert(sircc_cfg_types, (char *)sircc_cfg_type_array[i].key,
                        HT_INT32_TO_POINTER(sircc_cfg_type_array[i].type));
    }

    sircc_cfg_init(&sircc.cfg);

    if (sircc_cfg_load_directory(&sircc.cfg, dirpath) == -1) {
        sircc_cfg_free(&sircc.cfg);
        return -1;
    }

    return 0;
}

void
sircc_cfg_shutdown(void) {
    ht_table_delete(sircc_cfg_types);
    sircc_cfg_free(&sircc.cfg);
}

void
sircc_cfg_init(struct sircc_cfg *cfg) {
    memset(cfg, 0, sizeof(struct sircc_cfg));

    cfg->entries = ht_table_new(ht_hash_string, ht_equal_string);
}

void
sircc_cfg_free(struct sircc_cfg *cfg) {
    struct ht_table_iterator *it;
    struct sircc_cfg_entry *entry;

    it = ht_table_iterate(cfg->entries);
    while (ht_table_iterator_get_next(it, NULL, (void **)&entry) == 1)
        sircc_cfg_entry_delete(entry);
    ht_table_iterator_delete(it);

    ht_table_delete(cfg->entries);

    for (size_t i = 0; i < cfg->nb_servers; i++)
        sircc_free(cfg->servers[i]);
    sircc_free(cfg->servers);
}

int
sircc_cfg_load_directory(struct sircc_cfg *cfg, const char *dirpath) {
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/cfg", dirpath);
    if (sircc_cfg_load_file(cfg, path) == -1)
        return -1;

    return 0;
}

int
sircc_cfg_load_file(struct sircc_cfg *cfg, const char *path) {
    char *current_server;
    FILE *file;
    int lineno;

    file = fopen(path, "r");
    if (!file) {
        sircc_set_error("cannot open file %s: %m", path);
        return -1;
    }

    current_server = NULL;

    lineno = 0;

    for (;;) {
        const char *previous_server;
        struct sircc_cfg_entry *entry, *old_entry;
        char line[1024];
        int ret;

        if (!fgets(line, sizeof(line), file)) {
            if (feof(file)) {
                break;
            } else {
                sircc_set_error("cannot read file %s: %m", path);
                return -1;
            }
        }

        lineno++;

        line[strcspn(line, "\r\n")] = '\0';

        if (line[0] == '#') {
            /* Comment */
            continue;
        }

        previous_server = current_server;
        ret = sircc_cfg_entry_parse(&entry, line, &current_server);
        if (ret == 0) {
            /* Valid line with no entry (empty line or server line) */
            if (current_server != previous_server)
                sircc_cfg_add_server(&sircc.cfg, current_server);

            continue;
        }

        if (ret == -1) {
            sircc_set_error("syntax error in %s at line %d: %s",
                            path, lineno, sircc_get_error());
            goto error;
        }

        if (entry->type == SIRCC_CFG_STRING_LIST
         && ht_table_get(cfg->entries, entry->key, (void **)&old_entry) == 1) {
            sircc_cfg_entry_add_string(old_entry, entry->u.sl.strs[0]);
            sircc_cfg_entry_delete(entry);
        } else {
            ht_table_insert2(cfg->entries, entry->key, entry,
                             NULL, (void **)&old_entry);
            if (old_entry)
                sircc_cfg_entry_delete(old_entry);
        }
    }

    sircc_free(current_server);

    fclose(file);
    return 0;

error:
    sircc_free(current_server);
    fclose(file);

    return -1;
}

void
sircc_cfg_ssl_file_path(char *buf, const char *file, size_t sz) {
    if (file[0] == '/') {
        /* Absolute path */
        strlcpy(buf, file, sz);
    } else {
        /* Relative path */
        snprintf(buf, sz, "%s/ssl/%s", sircc.cfgdir, file);
    }
}

const char *
sircc_cfg_string(struct sircc_cfg *cfg, const char *key,
                 const char *default_value) {
    struct sircc_cfg_entry *entry;

    if (ht_table_get(cfg->entries, key, (void **)&entry) == 0)
        return default_value;

    return entry->u.s;
}

const char **
sircc_cfg_strings(struct sircc_cfg *cfg, const char *key, size_t *pnb) {
    struct sircc_cfg_entry *entry;

    if (ht_table_get(cfg->entries, key, (void **)&entry) == 0) {
        *pnb = 0;
        return NULL;
    }

    *pnb = entry->u.sl.nb;
    return (const char **)entry->u.sl.strs;
}

int
sircc_cfg_integer(struct sircc_cfg *cfg, const char *key, int default_value) {
    struct sircc_cfg_entry *entry;

    if (ht_table_get(cfg->entries, key, (void **)&entry) == 0)
        return default_value;

    return entry->u.i;
}

bool
sircc_cfg_boolean(struct sircc_cfg *cfg, const char *key, bool default_value) {
    struct sircc_cfg_entry *entry;

    if (ht_table_get(cfg->entries, key, (void **)&entry) == 0)
        return default_value;

    return entry->u.b;
}

const char *
sircc_cfg_server_string(struct sircc_server *server, const char *subkey,
                        const char *default_value) {
    char key[SIRCC_CFG_KEY_MAXSZ];

    snprintf(key, sizeof(key), "server.%s.%s", server->name, subkey);
    return sircc_cfg_string(&sircc.cfg, key, default_value);
}

const char **
sircc_cfg_server_strings(struct sircc_server *server, const char *subkey,
                         size_t *pnb) {
    char key[SIRCC_CFG_KEY_MAXSZ];

    snprintf(key, sizeof(key), "server.%s.%s", server->name, subkey);
    return sircc_cfg_strings(&sircc.cfg, key, pnb);
}

int
sircc_cfg_server_integer(struct sircc_server *server, const char *subkey,
                         int default_value) {
    char key[SIRCC_CFG_KEY_MAXSZ];

    snprintf(key, sizeof(key), "server.%s.%s", server->name, subkey);
    return sircc_cfg_integer(&sircc.cfg, key, default_value);
}

bool
sircc_cfg_server_boolean(struct sircc_server *server, const char *subkey,
                         bool default_value) {
    char key[SIRCC_CFG_KEY_MAXSZ];

    snprintf(key, sizeof(key), "server.%s.%s", server->name, subkey);
    return sircc_cfg_boolean(&sircc.cfg, key, default_value);
}

static void
sircc_cfg_add_server(struct sircc_cfg *cfg, const char *server_name) {
    if (!cfg->servers) {
        cfg->servers_sz = 4;
        cfg->nb_servers = 0;
        cfg->servers = sircc_calloc(cfg->servers_sz, sizeof(char *));
    } else if (cfg->nb_servers + 1 > cfg->servers_sz) {
        cfg->servers_sz *= 2;
        cfg->servers = sircc_realloc(cfg->servers,
                                     cfg->servers_sz * sizeof(char *));
        memset(cfg->servers + cfg->servers_sz / 2, 0,
               (cfg->servers_sz / 2) * sizeof(char *));
    }

    cfg->servers[cfg->nb_servers] = sircc_strdup(server_name);
    cfg->nb_servers++;
}

static int
sircc_cfg_get_key_type(const char *key, enum sircc_cfg_entry_type *ptype) {
    intptr_t value;

    if (ht_table_get(sircc_cfg_types, key, (void **)&value) == 0)
        return -1;

    *ptype = value;
    return 0;
}

static int
sircc_cfg_entry_parse(struct sircc_cfg_entry **pentry, const char *line,
                      char **pserver) {
    struct sircc_cfg_entry *entry;
    const char *ptr;
    char *key, *value;
    int ret;

    ptr = line;

    ret = sircc_cfg_parse_key_value(ptr, &key, &value);
    if (ret <= 0)
        return ret;

    if (strcmp(key, "server") == 0) {
        /* Set the current server name */
        sircc_free(*pserver);
        *pserver = value;

        sircc_free(key);
        return 0;
    }

    entry = sircc_malloc(sizeof(struct sircc_cfg_entry));
    memset(entry, 0, sizeof(struct sircc_cfg_entry));

    if (strcmp(key, "chan") == 0) {
        const char *space;
        char *chan_name, *chan_key, *chan_value;

        space = strchr(value, ' ');
        if (!space) {
            sircc_set_error("empty chan entry");
            sircc_free(key);
            sircc_free(value);
            goto error;
        }

        chan_name = sircc_strndup(value, (size_t)(space - value));

        ptr = space + 1;
        while (isspace((unsigned char)*ptr))
            ptr++;
        if (*ptr == '\0') {
            sircc_set_error("empty chan entry");
            sircc_free(key);
            sircc_free(value);
            sircc_free(chan_name);
            goto error;
        }

        ret = sircc_cfg_parse_key_value(ptr, &chan_key, &chan_value);
        if (ret <= 0) {
            sircc_free(key);
            sircc_free(value);
            sircc_free(chan_name);
            goto error;
        }

        sircc_asprintf(&entry->key, "server.%s.chan.%s.%s",
                       *pserver, chan_name, chan_key);

        sircc_free(chan_name);

        sircc_free(key);
        key = chan_key;

        sircc_free(value);
        value = chan_value;
    } else if (*pserver) {
        sircc_asprintf(&entry->key, "server.%s.%s", *pserver, key);
    } else {
        entry->key = sircc_strdup(key);
    }

    if (sircc_cfg_get_key_type(key, &entry->type) == -1) {
        sircc_set_error("unknown key '%s'", key);
        sircc_free(key);
        sircc_free(value);
        goto error;
    }

    if (sircc_cfg_entry_parse_value(entry, value) == -1) {
        sircc_free(key);
        sircc_free(value);
        goto error;
    }

    sircc_free(key);
    sircc_free(value);

    *pentry = entry;
    return 1;

error:
    sircc_cfg_entry_delete(entry);
    return -1;
}

static int
sircc_cfg_entry_parse_value(struct sircc_cfg_entry *entry, const char *str) {
    switch (entry->type) {
    case SIRCC_CFG_STRING:
        entry->u.s = sircc_strdup(str);
        break;

    case SIRCC_CFG_STRING_LIST:
        entry->u.sl.nb = 1;
        entry->u.sl.strs = sircc_malloc(sizeof(char *));
        entry->u.sl.strs[0] = sircc_strdup(str);
        break;

    case SIRCC_CFG_INTEGER:
        {
            long value;
            char *end;

            errno = 0;
            value = strtol(str, &end, 10);
            if (errno) {
                sircc_set_error("cannot parse integer value");
                return -1;
            }

            if (value < INT_MIN || value > INT_MAX) {
                sircc_set_error("integer too large");
                return -1;
            }

            if (*end != '\0') {
                sircc_set_error("invalid data after integer");
                return -1;
            }

            entry->u.i = value;
        }
        break;

    case SIRCC_CFG_BOOLEAN:
        if (strcmp(str, "yes") == 0) {
            entry->u.b = true;
        } else if (strcmp(str, "no") == 0) {
            entry->u.b = false;
        } else {
            sircc_set_error("cannot parse boolean value");
            return -1;
        }
        break;
    }

    return 0;
}

static void
sircc_cfg_entry_add_string(struct sircc_cfg_entry *entry, const char *str) {
    assert(entry->type == SIRCC_CFG_STRING_LIST);

    entry->u.sl.nb++;
    entry->u.sl.strs = sircc_realloc(entry->u.sl.strs,
                                     entry->u.sl.nb * sizeof(char *));
    entry->u.sl.strs[entry->u.sl.nb - 1] = sircc_strdup(str);
}

static void
sircc_cfg_entry_delete(struct sircc_cfg_entry *entry) {
    if (!entry)
        return;

    sircc_free(entry->key);

    switch (entry->type) {
    case SIRCC_CFG_STRING:
        sircc_free(entry->u.s);
        break;

    case SIRCC_CFG_STRING_LIST:
        for (size_t i = 0; i < entry->u.sl.nb; i++)
            sircc_free(entry->u.sl.strs[i]);
        sircc_free(entry->u.sl.strs);
        break;

    default:
        break;
    }

    sircc_free(entry);
}

static int
sircc_cfg_parse_key_value(const char *ptr, char **pkey, char **pvalue) {
    const char *space;
    char *key, *value;
    size_t toklen;

    key = NULL;
    value = NULL;

    while (isspace((unsigned char)*ptr))
        ptr++;
    if (*ptr == '\0')
        return 0;

    /* Read the key */
    space = strchr(ptr, ' ');
    if (!space) {
        sircc_set_error("missing value");
        goto error;
    }

    toklen = (size_t)(space - ptr);
    if (toklen == 0) {
        sircc_set_error("missing key");
        goto error;
    }

    key = sircc_strndup(ptr, toklen);

    /* Skip spaces */
    ptr = space + 1;
    while (isspace((unsigned char)*ptr))
        ptr++;

    if (*ptr == '\0') {
        sircc_set_error("missing value");
        goto error;
    }

    /* Read the value */
    value = sircc_strdup(ptr);

    *pkey = key;
    *pvalue = value;

    return 1;

error:
    sircc_free(key);
    sircc_free(value);

    return -1;
}
