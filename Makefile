CFLAGS       = -std=c99 -Wall -Wextra -pedantic -O2
VENDORCFLAGS = -std=c99 -O2

OBJ = cmd/dump.o cmd/sha256.o cmd/tweetnacl.o

cmd/dump: $(OBJ)
	$(CC) -o $@ $(OBJ)

cmd/dump.o: cmd/dump.c cmd/sha256.h cmd/tweetnacl.h
	$(CC) $(CFLAGS) -c -o $@ cmd/dump.c

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

# Every meta file claims a source. verify is the evidence: gen exits
# non-zero if regenerating against the pinned checkout would change any
# committed byte. Needs Python and the checkout; check alone does not.
verify: check
	tools/gen

clean:
	rm -f cmd/dump $(OBJ)

.PHONY: check gen verify clean
