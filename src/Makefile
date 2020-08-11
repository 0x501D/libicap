CC = gcc
CFLAGS = -O0 -ggdb -Wall -Wextra -Wformat-security -pedantic -fvisibility=hidden -shared -fPIC
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)
DEP = $(OBJ:.o=.d)

libicap.so: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

-include $(DEP)

%.d: %.c
	@$(CC) $< -MM -MT $(@:.d=.o) >$@

test_single:
	$(MAKE) -C test all TESTFLAGS=-DIC_TEST_SINGLE

test_multi:
	$(MAKE) -C test all TESTFLAGS=-DIC_TEST_MULTI

test_clean:
	$(MAKE) -C test clean

clean:
	rm -f libicap.so *.o *.d

.PHONY: test_single test_multi clean test_clean
