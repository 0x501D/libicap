all:
	gcc -O2 -fvisibility=hidden -Wall -Wextra -Wformat-security -pedantic -shared -fPIC libicap.c -o libicap.so

demo: all
	gcc demo.c -Wall -I. -L. -licap	-o demo

clean:
	rm -f libicap.so demo

.PHONY: all test clean
