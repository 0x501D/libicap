CC = gcc
CFLAGS = -Wall -Wextra -Wformat-security -Wl,-soname,libicap.so.0 \
				 -pedantic -fvisibility=hidden -shared -fPIC
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)
DEP = $(OBJ:.o=.d)

libicap.so: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

-include $(DEP)

%.d: %.c
	@$(CC) $< -MM -MT $(@:.d=.o) >$@

debug: CFLAGS += -O0 -ggdb
debug: libicap.so

install: libicap.so
	ln -sf libicap.so libicap.so.0

test_single:
	$(MAKE) -C test all TESTFLAGS=-DIC_TEST_SINGLE

test_multi:
	$(MAKE) -C test all TESTFLAGS=-DIC_TEST_MULTI

test_clean:
	$(MAKE) -C test clean

clean:
	rm -f libicap.so libicap.so.0 *.o *.d

.PHONY: test_single test_multi clean test_clean install
