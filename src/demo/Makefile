CC = gcc
CFLAGS = -O0 -ggdb -I../../ -Wall -Wextra -Wformat-security -pedantic
LDFLAGS = -L../ -licap

ic_demo_cl: ic_demo_cl.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

ic_demo_chunked: ic_demo_chunked.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

ic_demo_raw: ic_demo_raw.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

all: ic_demo_cl ic_demo_chunked ic_demo_raw

clean:
	rm -f *.o ic_demo_cl ic_demo_chunked ic_demo_raw

.PHONY: clean
