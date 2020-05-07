all:
	gcc -O0 -ggdb -fvisibility=hidden -Wall -Wextra -Wformat-security -pedantic -shared -fPIC libicap.c -o libicap.so

demo: all
	gcc demo.c -O0 -ggdb -Wall -I. -L. -licap -o demo

clean:
	rm -f libicap.so demo

.PHONY: all test clean
