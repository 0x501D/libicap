CC = gcc
CFLAGS = -O0 -ggdb -I../../ -Wall -Wextra -Wformat-security -pedantic
CFLAGS += $(TESTFLAGS)
LDFLAGS = -L../ -licap

ic_test_cl: ic_test_cl.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

ic_test_chunked: ic_test_chunked.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

ic_test_raw: ic_test_raw.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

all: ic_test_cl ic_test_chunked ic_test_raw

clean:
	rm -f *.o ic_test_cl ic_test_chunked ic_test_raw

.PHONY: clean
