CC = gcc
CFLAGS = -O0 -ggdb -I../../ -Wall -Wextra -Wformat-security -pedantic
LDFLAGS = -L../ -licap

ic_demo: ic_demo.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f *.o ic_demo

.PHONY: clean
