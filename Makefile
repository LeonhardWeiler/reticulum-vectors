CFLAGS = -std=c99 -Wall -Wextra -pedantic -O2

cmd/dump: cmd/dump.c cmd/sha256.c cmd/sha256.h
	$(CC) $(CFLAGS) -o $@ cmd/dump.c cmd/sha256.c

check: cmd/dump
	cmd/check

gen:
	tools/gen

clean:
	rm -f cmd/dump

.PHONY: check gen clean
