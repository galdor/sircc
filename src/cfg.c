/*
 * Copyright (c) 2013-2015 Nicolas Martyanoff
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

static int sircc_cfg_load_file(const char *);

static struct sircc_server *sircc_cfg_load_server(const char *,
                                                  const struct json_value *);
static int sircc_cfg_load_highlights(const struct json_value *,
                                     struct c_vector *);

void
sircc_cfg_initialize() {
    char *path;

    c_asprintf(&path, "%s/cfg.json", sircc.cfgdir);
    if (sircc_cfg_load_file(path) == -1)
        die("cannot load configuration from %s: %s", path, c_get_error());
    c_free(path);
}

void
sircc_cfg_shutdown(void) {
}

static int
sircc_cfg_load_file(const char *path) {
    struct json_value *json;
    uint32_t flags;

    flags = JSON_PARSE_REJECT_DUPLICATE_KEYS
          | JSON_PARSE_REJECT_NULL_CHARACTERS;
    json = json_parse_file(path, flags);
    if (!json)
        return -1;

#define SIRCC_FAIL(fmt_, ...)             \
    do {                                  \
        c_set_error(fmt_, ##__VA_ARGS__); \
        json_value_delete(json);          \
        return -1;                        \
    } while (0)

    if (!json_value_is_object(json))
        SIRCC_FAIL("top-level value is not an object");

    for (size_t i = 0; i < json_object_nb_members(json); i++) {
        const char *key;
        struct json_value *value;

        key = json_object_nth_member(json, i, &value);

        if (strcmp(key, "highlights") == 0) {
            struct c_vector *highlighters;

            highlighters = c_vector_new(sizeof(struct sircc_highlighter));

            if (sircc_cfg_load_highlights(value, highlighters) == -1) {
                for (size_t i = 0; i < c_vector_length(highlighters); i++)
                    sircc_highlighter_free(c_vector_entry(highlighters, i));
                c_vector_delete(highlighters);
                return -1;
            }

            sircc.highlighters = highlighters;
        } else if (strcmp(key, "servers") == 0) {
            struct c_ptr_vector *servers;

            if (!json_value_is_object(json))
                SIRCC_FAIL("servers are not an object");

            servers = c_ptr_vector_new();

            for (size_t j = 0; j < json_object_nb_members(value); j++) {
                const char *skey;
                struct json_value *svalue;
                struct sircc_server *server;

                skey = json_object_nth_member(value, j, &svalue);

                server = sircc_cfg_load_server(skey, svalue);
                if (!server) {
                    c_set_error("invalid server '%s': %s", skey, c_get_error());

                    for (size_t i = 0; i < c_ptr_vector_length(servers); i++)
                        sircc_server_delete(c_ptr_vector_entry(servers, i));
                    c_ptr_vector_delete(servers);
                    return -1;
                }

                c_ptr_vector_append(servers, server);
            }

            if (c_ptr_vector_length(servers) == 0)
                die("no server defined in configuration");

            sircc.servers = servers;
        } else {
            SIRCC_FAIL("unknown key '%s'", key);
        }
    }

#undef SIRCC_FAIL

    json_value_delete(json);
    return 0;
}

static struct sircc_server *
sircc_cfg_load_server(const char *name, const struct json_value *json) {
    struct sircc_server *server;
    const char *string;
    int64_t i64;

    server = sircc_server_new(name);

#define SIRCC_FAIL(fmt_, ...)             \
    do {                                  \
        c_set_error(fmt_, ##__VA_ARGS__); \
        sircc_server_delete(server);      \
        return NULL;                      \
    } while (0)

    if (!json_value_is_object(json))
        SIRCC_FAIL("server description is not an object");

    for (size_t i = 0; i < json_object_nb_members(json); i++) {
        const char *key;
        struct json_value *value;

        key = json_object_nth_member(json, i, &value);

        if (strcmp(key, "host") == 0) {
            if (!json_value_is_string(value))
                SIRCC_FAIL("host is not a string");

            server->host = json_string_dup(value);
        } else if (strcmp(key, "port") == 0) {
            if (!json_value_is_integer(value))
                SIRCC_FAIL("port is not an integer");

            i64 = json_integer_value(value);
            if (i64 < 1 || i64 > 65535)
                SIRCC_FAIL("invalid port");

            server->port = (uint16_t)i64;
        } else if (strcmp(key, "autoConnect") == 0) {
            if (!json_value_is_boolean(value))
                SIRCC_FAIL("autoConnect is not a boolean");

            server->auto_connect = json_boolean_value(value);
        } else if (strcmp(key, "ssl") == 0) {
            if (!json_value_is_boolean(value))
                SIRCC_FAIL("ssl is not a boolean");

            server->use_ssl = json_boolean_value(value);
        } else if (strcmp(key, "sslCaCertificate") == 0) {
            if (!json_value_is_string(value))
                SIRCC_FAIL("sslCaCertificate is not a string");

            string = json_string_value(value);

            if (string[0] == '/') {
                server->ssl_ca_cert = json_string_dup(value);
            } else {
                c_asprintf(&server->ssl_ca_cert, "%s/ssl/%s",
                           sircc.cfgdir, json_string_value(value));
            }
        } else if (strcmp(key, "password") == 0) {
            if (!json_value_is_string(value))
                SIRCC_FAIL("password is not a string");

            server->password = json_string_dup(value);
        } else if (strcmp(key, "nickname") == 0) {
            if (!json_value_is_string(value))
                SIRCC_FAIL("nickname is not a string");

            server->nickname = json_string_dup(value);
            server->current_nickname = json_string_dup(value);
        } else if (strcmp(key, "realname") == 0) {
            if (!json_value_is_string(value))
                SIRCC_FAIL("realname is not a string");

            server->realname = json_string_dup(value);
        } else if (strcmp(key, "maxNicknameLength") == 0) {
            if (!json_value_is_integer(value))
                SIRCC_FAIL("maxNicknameLength is not a string");

            i64 = json_integer_value(value);
            if (i64 < 1 || i64 > 128)
                SIRCC_FAIL("invalid maxNicknameLength");

            server->max_nickname_length = (int)i64;
        } else if (strcmp(key, "autoJoin") == 0) {
            if (!json_value_is_array(value))
                SIRCC_FAIL("autoJoin is not an array");

            for (size_t j = 0; j < json_array_nb_elements(value); j++) {
                const struct json_value *evalue;

                evalue = json_array_element(value, j);
                if (!json_value_is_string(evalue))
                    SIRCC_FAIL("autoJoin element is not a string");

                c_ptr_vector_append(server->auto_join,
                                    json_string_dup(evalue));
            }
        } else if (strcmp(key, "autoCommands") == 0) {
            if (!json_value_is_array(value))
                SIRCC_FAIL("autoCommands are not an array");

            for (size_t j = 0; j < json_array_nb_elements(value); j++) {
                const struct json_value *evalue;

                evalue = json_array_element(value, j);
                if (!json_value_is_string(evalue))
                    SIRCC_FAIL("autoCommands element is not a string");

                c_ptr_vector_append(server->auto_commands,
                                    json_string_dup(evalue));
            }
        } else {
            SIRCC_FAIL("unknown key '%s'", key);
        }
    }

    if (!server->host)
        SIRCC_FAIL("missing host");

#undef SIRCC_FAIL

    return server;
}

static int
sircc_cfg_load_highlights(const struct json_value *json,
                          struct c_vector *highlighters) {
#define SIRCC_FAIL(fmt_, ...)             \
    do {                                  \
        c_set_error(fmt_, ##__VA_ARGS__); \
        return -1;                        \
    } while (0)

    if (!json_value_is_object(json))
        SIRCC_FAIL("highlights are not an object");

    for (size_t i = 0; i < json_object_nb_members(json); i++) {
        const char *key;
        struct json_value *value;
        struct sircc_highlighter highlighter;
        pcre_extra *extra;
        const char *string;
        size_t length;

        key = json_object_nth_member(json, i, &value);

        if (!json_value_is_string(value))
            SIRCC_FAIL("highlight value is not a string");

        sircc_highlighter_init(&highlighter);

        highlighter.regexp = sircc_pcre_compile(key, &extra);
        if (!highlighter.regexp) {
            sircc_highlighter_free(&highlighter);
            SIRCC_FAIL("cannot compile regexp /%s/: %s", key, c_get_error());
        }
        highlighter.regexp_extra = extra;

        string = json_string_value(value);
        length = json_string_length(value);
        if (sircc_highlighter_init_escape_sequences(&highlighter,
                                                    string, length) == -1) {
            sircc_highlighter_free(&highlighter);
            SIRCC_FAIL("invalid highlight value: %s", c_get_error());
        }

        c_vector_append(highlighters, &highlighter);
    }

#undef SIRCC_FAIL

    return 0;
}
