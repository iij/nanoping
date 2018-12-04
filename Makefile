CFLAGS=-Wall -Werror -std=gnu11 -O2
LDFLAGS=-lpthread
CC=clang

all: nanoping

OBJS = nanoping_main.o nanoping_common.o
nanoping: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -rf *.o nanoping

install:
	cp nanoping /usr/local/bin/
