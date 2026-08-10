CFLAGS       = -std=c99 -Wall -Wextra -pedantic -O2 \
               -Wshadow -Wcast-qual -Wwrite-strings \
               -Wstrict-prototypes -Wmissing-prototypes
VENDORCFLAGS = -std=c99 -O2

OBJ = cmd/dump.o cmd/sha256.o cmd/hmac.o cmd/aes256.o cmd/tweetnacl.o

cmd/dump: $(OBJ)
	$(CC) -o $@ $(OBJ)

cmd/dump.o: cmd/dump.c cmd/sha256.h cmd/hmac.h cmd/aes256.h cmd/tweetnacl.h
	$(CC) $(CFLAGS) -c -o $@ cmd/dump.c

cmd/hmac.o: cmd/hmac.c cmd/hmac.h cmd/sha256.h
	$(CC) $(CFLAGS) -c -o $@ cmd/hmac.c

cmd/aes256.o: cmd/aes256.c cmd/aes256.h
	$(CC) $(CFLAGS) -c -o $@ cmd/aes256.c

cmd/sha256.o: cmd/sha256.c cmd/sha256.h
	$(CC) $(CFLAGS) -c -o $@ cmd/sha256.c

# Vendored, kept verbatim. Built without the warning flags applied to
# the corpus's own code. See cmd/VENDOR.
cmd/tweetnacl.o: cmd/tweetnacl.c cmd/tweetnacl.h
	$(CC) $(VENDORCFLAGS) -c -o $@ cmd/tweetnacl.c

check: cmd/dump
	cmd/check

gen:
	tools/gen

# Every meta file claims a source and cmd/VENDOR says the vendored file
# is unmodified. verify is the evidence for both. Needs Python and the
# checkout; check alone does not, which is why none of this is in
# cmd/check.
#
# Two claims are read against what they describe: dump -l against the
# kinds in test/INDEX, and the hashes in cmd/VENDOR against the files.
# Both sides of both are machine output.
#
# The hashes go through grep because the first of the two lines carries
# a label and sha256sum would skip it, checking one file of two and
# exiting zero.
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
