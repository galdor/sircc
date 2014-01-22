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

#include <X11/Xatom.h>

#include "sircc.h"

static int sircc_x11_error_handler(Display *, XErrorEvent *);

void
sircc_x11_initialize(void) {
    const char *display_name;

    XSetErrorHandler(sircc_x11_error_handler);

    display_name = getenv("DISPLAY");
    if (!display_name)
        return;

    sircc.display = XOpenDisplay(display_name);
    if (!sircc.display) {
        /* Having no X11 server running is not an error */
        return;
    }

    sircc.window = XCreateSimpleWindow(sircc.display,
                                       DefaultRootWindow(sircc.display),
                                       0, 0, 1, 1, 0, 0, 0);
}

void
sircc_x11_shutdown(void) {
    if (sircc.display)
        XCloseDisplay(sircc.display);
}

char *
sircc_x11_primary_selection(void) {
    Window win_requestor;
    Atom property, type;
    unsigned char *data_tmp;
    unsigned long nb_items, bytes_left;
    long offset; /* 32 bit items */
    int format, ret;
    size_t length;

    char *data;
    size_t datasz;

    data_tmp = NULL;

    if (!sircc.display)
        return NULL;

    XConvertSelection(sircc.display, XA_PRIMARY, XA_STRING, None,
                      sircc.window, CurrentTime);
    XFlush(sircc.display);

    for (;;) {
        XEvent event;

        XNextEvent(sircc.display, &event);
        if (event.type != SelectionNotify)
            continue;

        win_requestor = event.xselection.requestor;
        property = event.xselection.property;
        break;
    }

    data = NULL;
    datasz = 0;
    offset = 0;

    for (;;) {
        ret = XGetWindowProperty(sircc.display, win_requestor, property,
                                 offset, 128, False, AnyPropertyType,
                                 &type, &format, &nb_items, &bytes_left,
                                 &data_tmp);
        if (ret != Success) {
            sircc_chan_log_error(NULL, "cannot fetch X11 selection");
            sircc_free(data);
            return NULL;
        }

        if (nb_items == 0)
            break;

        if (type != XA_STRING) {
            if (type == None) {
                sircc_chan_log_error(NULL, "empty selection data type");
            } else {
                sircc_chan_log_error(NULL, "unhandled selection data type %s",
                                     XGetAtomName(sircc.display, type));
            }

            goto error;
        }

        switch (format) {
        case 8:
            length = (size_t)nb_items;
            offset += nb_items / 4;
            break;

        case 16:
            length = (size_t)(nb_items * 2);
            offset += nb_items / 2;
            break;

        case 32:
            length = (size_t)(nb_items * 4);
            offset += nb_items;
            break;

        default:
            sircc_chan_log_error(NULL, "unhandled selection data format %d",
                                 format);
            goto error;
        }

        if (!data) {
            datasz = length + 1;
            data = sircc_malloc(datasz);
            strlcpy(data, (char *)data_tmp, datasz);
        } else {
            datasz += length;
            data = sircc_realloc(data, datasz);
            strlcpy(data + datasz - length - 1,
                    (char *)data_tmp, datasz);
        }

        XFree(data_tmp);

        if (bytes_left == 0)
            break;
    }

    return data;

error:
    sircc_free(data);

    if (data_tmp)
        XFree(data_tmp);

    return NULL;
}

static int
sircc_x11_error_handler(Display *display, XErrorEvent *event) {
    char error_str[SIRCC_ERROR_BUFSZ];

    XGetErrorText(display, event->error_code, error_str, sizeof(error_str));

    sircc_chan_log_error(NULL, "X11 error: %s", error_str);

    return 0;
}
