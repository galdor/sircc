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

#ifdef SIRCC_PLATFORM_FREEBSD
#   include <sys/socket.h>
#   include <netinet.h>
#endif

#include "sircc.h"

int
sircc_address_resolve(const char *host, const char *port,
                      struct addrinfo ***paddresses, size_t *psz) {
    struct addrinfo hints, *res, *ai;
    struct addrinfo **addresses;
    size_t nb_addresses;
    int ret, i;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = 0;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_addrlen = 0;

    ret = getaddrinfo(host, port, &hints, &res);
    if (ret != 0) {
        sircc_set_error("cannot resolve address %s:%s: %s",
                        host, port, gai_strerror(ret));
        return -1;
    }

    nb_addresses = 0;
    for (ai = res; ai; ai = ai->ai_next)
        nb_addresses++;

    addresses = sircc_calloc(nb_addresses, sizeof(struct addrinfo *));

    i = 0;
    for (ai = res; ai; ai = ai->ai_next) {
        addresses[i] = ai;
        i++;
    }

    *paddresses = addresses;
    *psz = nb_addresses;
    return 0;
}

int
sircc_socket_open(struct addrinfo *ai) {
    int sock, flags;

    sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock == -1) {
        sircc_set_error("cannot create socket: %s", strerror(errno));
        return -1;
    }

    flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) {
        sircc_set_error("cannot get socket flags: %s", strerror(errno));
        close(sock);
        return -1;
    }

    flags |= O_NONBLOCK;

    if (fcntl(sock, F_SETFL, flags) == -1) {
        sircc_set_error("cannot set socket flags: %s", strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

int
sircc_socket_get_so_error(int sock, int *perr) {
    socklen_t len;

    len = sizeof(*perr);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, perr, &len) == -1) {
        sircc_set_error("cannot get socket info: %s", strerror(errno));
        return -1;
    }

    return 0;
}
