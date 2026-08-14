CFLAGS       = -std=c99 -Wall -Wextra -pedantic -O2 \
               -Wshadow -Wcast-qual -Wwrite-strings \
               -Wstrict-prototypes -Wmissing-prototypes
VENDORCFLAGS = -std=c99 -O2

OBJ = cmd/dump.o cmd/sha256.o cmd/hmac.o cmd/aes.o cmd/tweetnacl.o

cmd/dump: $(OBJ)
	$(CC) -o $@ $(OBJ)

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ): cmd/sha256.h cmd/hmac.h cmd/aes.h cmd/tweetnacl.h

cmd/tweetnacl.o: cmd/tweetnacl.c
	$(CC) $(VENDORCFLAGS) -c -o $@ cmd/tweetnacl.c

check: cmd/dump
	cmd/check

gen:
	tools/gen

verify: check
	{ cmd/dump -l | LC_ALL=C sort -u; \
	  cut -d/ -f1 test/INDEX | LC_ALL=C sort -u; } | LC_ALL=C sort | uniq -c \
	  | awk '$$1 != 2 { print "cmd/dump -l and test/INDEX disagree on " $$2; bad = 1 } \
	         END { exit bad }'
	cd cmd && grep -oE '[0-9a-f]{64}  tweetnacl\.[ch]' VENDOR | sha256sum -c
	tools/gen

clean:
	rm -f cmd/dump $(OBJ)

help:
	@echo 'make            build cmd/dump'
	@echo 'make check      run every vector against cmd/dump'
	@echo 'make gen        regenerate the vectors; needs Python and the checkout'
	@echo 'make verify     check, then regenerate every vector and diff it'
	@echo 'make clean      remove cmd/dump and the objects'
	@echo
	@echo 'DUMP=./mine cmd/check       check another implementation'
	@echo 'DUMP=./mine ENCODE=no ...   skip the round trip'
	@echo 'cmd/dump -l                 list the kinds a decoder can be asked for'

.PHONY: check gen verify clean help
