CC=gcc -std=c99 -pedantic
CFLAGS=-Wall -Werror -g

valloc.o: valloc.c valloc.h
	$CC -c valloc.c $CFLAGS

example: example.c valloc.o
	$CC -o example example.c valloc.o $CFLAGS
