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

#include "sircc.h"

void
sircc_cmd_free(struct sircc_cmd *cmd) {
    sircc_free(cmd->name);

    for (size_t i = 0; i < cmd->nb_args; i++)
        sircc_free(cmd->args[i]);
}

int
sircc_cmd_parse(struct sircc_cmd *cmd, struct sircc_buf *buf) {
    struct sircc_msg msg;
    int ret;

    /* Reuse the IRC parser for the time being */

    sircc_buf_skip(&sircc.prompt_buf, 1); /* '/' */
    sircc_buf_add(&sircc.prompt_buf, "\r\n", 2);

    ret = sircc_msg_parse(&msg, buf);
    if (ret <= 0)
        return ret;

    cmd->name = msg.command;
    cmd->nb_args = msg.nb_params;
    cmd->args = msg.params;

    if (msg.prefix)
        sircc_free(msg.prefix);

    return 1;
}

void
sircc_cmd_run(struct sircc_cmd *cmd) {
    sircc_chan_log_info(NULL, "command: %s/%zu", cmd->name, cmd->nb_args);
}
