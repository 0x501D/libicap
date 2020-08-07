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

demo:
	$(MAKE) -C demo all

clean_demo:
	$(MAKE) -C demo clean

clean:
	rm -f libicap.so *.o *.d

.PHONY: demo clean clean_demo
