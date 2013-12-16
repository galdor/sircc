# Common
prefix= /usr/local
bindir= $(prefix)/bin

CC=   clang

CFLAGS+= -std=c99
CFLAGS+= -Wall -Wextra -Werror -Wsign-conversion
CFLAGS+= -Wno-unused-parameter -Wno-unused-function

LDFLAGS=

# Platform specific
platform= $(shell uname -s)

ifeq ($(platform), Linux)
	CFLAGS+= -DSIRCC_PLATFORM_LINUX
	CFLAGS+= -D_POSIX_C_SOURCE=200809L -D_BSD_SOURCE
endif

# Debug
debug=0
ifeq ($(debug), 1)
	CFLAGS+= -g -ggdb
else
	CFLAGS+= -O2
endif

# Target: sircc
sircc_BIN= sircc
sircc_HDR= $(wildcard src/*.h)
sircc_SRC= $(wildcard src/*.c)
sircc_OBJ= $(subst .c,.o,$(sircc_SRC))

$(sircc_BIN): CFLAGS+=
$(sircc_BIN): LDFLAGS+=
$(sircc_BIN): LDLIBS+= -lncurses

# Rules
all: bin

bin: $(sircc_BIN)

$(sircc_OBJ): $(sircc_HDR)
$(sircc_BIN): $(sircc_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:
	$(RM) $(sircc_BIN) $(wildcard src/*.o)

install: bin
	mkdir -p $(bindir)
	install -m 755 $(sircc_BIN) $(bindir)

uninstall:
	$(RM) $(addprefix $(bindir)/,$(sircc_BIN))

tags:
	ctags -o .tags -a $(wildcard src/*.[hc])

.PHONY: all bin clean install uninstall tags
