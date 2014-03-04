# Common
version= $(shell cat version)
#build_id= $(shell [ -d .git ] && git describe --tags --dirty)
build_id =

prefix= /usr/local
bindir= $(prefix)/bin

debug_file= "/tmp/sircc.debug"

CC= clang

CFLAGS+= -std=c99
CFLAGS+= -Wall -Wextra -Werror -Wsign-conversion
CFLAGS+= -Wno-unused-parameter -Wno-unused-function

CFLAGS+= -DSIRCC_VERSION=\"$(version)\"
CFLAGS+= -DSIRCC_BUILD_ID=\"$(build_id)\"
CFLAGS+= -DSIRCC_DEBUG_FILE=\"$(debug_file)\"

LDFLAGS=

# Platform specific
platform= $(shell uname -s)

ifeq ($(platform), Linux)
	CFLAGS+= -DSIRCC_PLATFORM_LINUX
	CFLAGS+= -D_XOPEN_SOURCE=700 -D_BSD_SOURCE
endif
ifeq ($(platform), FreeBSD)
	CFLAGS+= -DSIRCC_PLATFORM_FREEBSD
	CFLAGS+= -I/usr/local/include
	LDFLAGS+= -L/usr/local/lib
endif
ifeq ($(platform), Darwin)
	CFLAGS+= -DSIRCC_PLATFORM_DARWIN
	CFLAGS+= -I/opt/local/include
	LDFLAGS+= -L/opt/local/lib
	LDLIBS+= -liconv
endif

# Debug
debug=0
ifeq ($(debug), 1)
	CFLAGS+= -g -ggdb
else
	CFLAGS+= -O2
endif

# Options
with_x11= 1

ifeq ($(with_x11), 1)
	CFLAGS+= -DSIRCC_WITH_X11
	LDLIBS+= -lX11
endif

# Target: sircc
sircc_BIN= sircc
sircc_HDR= $(wildcard src/*.h)
sircc_SRC= $(wildcard src/*.c)
ifneq ($(with_x11), 1)
	sircc_SRC:= $(filter-out src/x11.c,$(sircc_SRC))
endif
sircc_OBJ= $(subst .c,.o,$(sircc_SRC))

$(sircc_BIN): CFLAGS+=  -Ilibhashtable/src -Ilibbuffer/src
$(sircc_BIN): LDFLAGS+= -Llibhashtable -Llibbuffer
$(sircc_BIN): LDLIBS+=  -lhashtable -lbuffer -lncursesw -lcrypto -lssl -lpcre

# Rules
all: bin

bin: deps $(sircc_BIN)

deps:
	$(MAKE) -C libhashtable lib
	$(MAKE) -C libbuffer lib

$(sircc_OBJ): $(sircc_HDR)
$(sircc_BIN): $(sircc_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:
	$(MAKE) -C libhashtable clean
	$(MAKE) -C libbuffer clean
	$(RM) $(sircc_BIN) $(wildcard src/*.o)

install: bin
	mkdir -p $(bindir)
	install -m 755 $(sircc_BIN) $(bindir)

uninstall:
	$(RM) $(addprefix $(bindir)/,$(sircc_BIN))

tags:
	ctags -o .tags -a \
		$(wildcard src/*.[hc]) \
		$(wildcard libhashtable/src/*.[hc]) \
		$(wildcard libbuffer/src/*.[hc])

.PHONY: all bin clean install uninstall tags
