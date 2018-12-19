CFLAGS=-Wall -Werror -std=gnu11 -O2
LDFLAGS=-lpthread
CC=clang

all: phctune

PHCTUNEOBJS = phctune.o
phctune: $(PHCTUNEOBJS)
	$(CC) -o $@ $(PHCTUNEOBJS) $(LDFLAGS)
clean:
	rm -rf *.o phctune
