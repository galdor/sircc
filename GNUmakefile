# Common
prefix= /usr/local
bindir= $(prefix)/bin

CC= clang

CFLAGS+= -std=c99
CFLAGS+= -Wall -Wextra -Werror -Wsign-conversion
CFLAGS+= -Wno-unused-parameter -Wno-unused-function

LDFLAGS=

# Platform specific
platform= $(shell uname -s)

ifeq ($(platform), Linux)
	CFLAGS+= -DSIRCC_PLATFORM_LINUX
	CFLAGS+= -D_XOPEN_SOURCE=700 -D_BSD_SOURCE
endif
ifeq ($(platform), FreeBSD)
	CFLAGS+= -DSIRCC_PLATFORM_FREEBSD
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

$(sircc_BIN): CFLAGS+=  -Ilibhashtable/src
$(sircc_BIN): LDFLAGS+= -Llibhashtable
$(sircc_BIN): LDLIBS+=  -lhashtable -lncursesw -lcrypto -lssl

# Rules
all: bin

bin: deps $(sircc_BIN)

deps:
	$(MAKE) -C libhashtable lib

$(sircc_OBJ): $(sircc_HDR)
$(sircc_BIN): $(sircc_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:
	$(MAKE) -C libhashtable clean
	$(RM) $(sircc_BIN) $(wildcard src/*.o)

install: bin
	mkdir -p $(bindir)
	install -m 755 $(sircc_BIN) $(bindir)

uninstall:
	$(RM) $(addprefix $(bindir)/,$(sircc_BIN))

tags:
	ctags -o .tags -a \
		$(wildcard src/*.[hc]) \
		$(wildcard libhashtable/src/*.[hc])

.PHONY: all bin clean install uninstall tags
