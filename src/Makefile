CC = gcc
CFLAGS = -O0 -ggdb -I../ -Wall -Wextra -Wformat-security -pedantic -fvisibility=hidden -shared -fPIC
LDFLAGS = -L. -licap
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)
DEP = $(OBJ:.o=.d)

libicap.so: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

-include $(DEP)

%.d: %.c
	@$(CC) -shared -fPIC $< -MM -MT $(@:.d=.o) >$@

demo:
	$(MAKE) -C demo

clean:
	rm -f libicap.so *.o *.d

.PHONY: demo clean
