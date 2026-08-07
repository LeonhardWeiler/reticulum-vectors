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

# Every meta file claims a source, doc/ cites the reference by line, and
# cmd/VENDOR says the vendored file is unmodified. verify is the
# evidence for all three. Needs Python and the checkout; check alone
# does not.
#
# The hashes are read through grep because the first of the two lines
# carries a label and sha256sum skips it, checking one file of two and
# exiting zero.
#
# The list of entry points in cmd/VENDOR is read the same way, against
# nm. It is the one claim in that file about this program rather than
# about the vendored one, and it had gone stale twice: once when
# test/sign added signing and once when the link vectors added the
# X25519 exchange. The sed strips tweetnacl's own suffixes, so the file
# can name crypto_sign where the object names
# crypto_sign_ed25519_tweet.
#
# dump -l is read the same way, against test/INDEX. README and
# doc/harness both send a harness author to it for the list of kinds,
# and nothing compared it to the corpus: a kind added to test/ and not
# to the list would leave that answer short by one, silently, in the one
# place a reader is told to trust it.
#
# README prints one vector whole, and those thirty-one lines are the
# largest stretch of prose in the repository that restates bytes. They
# are folded to fit the page: a value too long for the line is
# continued below it, indented past the column values start in. That is
# the one rule the unfolding needs. A continuation joins with a space
# in meta, where the value is a sentence, and with nothing in raw and
# expect, where it is a hex string.
#
# Only the first disagreement per file is printed. A line dropped in
# README shifts every line below it, and sixteen complaints locate the
# drift no better than one. The line counts are printed either way,
# which is what tells a shift from a changed byte.
#
# Not in cmd/check: that is the consumer contract, and a consumer needs
# test/, doc/ and cmd/ and no README.
verify: check
	awk 'NR == FNR { \
	       if ($$0 == "One vector, whole") { block = 1; next } \
	       if (!block || $$0 == "") next; \
	       match($$0, /^ */); indent = RLENGTH; \
	       if (indent == 4 && $$0 ~ /^ +(meta|raw|expect)$$/) { sec = $$1; next } \
	       if (sec == "") next; \
	       sub(/^ +/, ""); \
	       if (indent == 8) readme[sec, ++lines[sec]] = $$0; \
	       else if (indent > 8) \
	         readme[sec, lines[sec]] = readme[sec, lines[sec]] (sec == "meta" ? " " : "") $$0; \
	       else block = 0; \
	       next } \
	     { file = FILENAME; sub(/.*\//, "", file); held[file] = FNR; \
	       if ($$0 != readme[file, FNR]) { bad = 1; \
	         if (!said[file]++) { \
	           print "README and " FILENAME " disagree on line " FNR; \
	           print "  README " readme[file, FNR]; \
	           print "  vector " $$0 } } } \
	     END { split("meta raw expect", name, " "); \
	       for (i = 1; i <= 3; i++) { s = name[i]; \
	         if (lines[s] != held[s]) { bad = 1; \
	           print "README gives " lines[s] + 0 " lines of " s \
	                 ", the vector holds " held[s] } } \
	       exit bad }' \
	  README test/pathrequest/tagged/meta test/pathrequest/tagged/raw \
	  test/pathrequest/tagged/expect
	{ cmd/dump -l | LC_ALL=C sort -u; \
	  cut -d/ -f1 test/INDEX | LC_ALL=C sort -u; } | LC_ALL=C sort | uniq -c \
	  | awk '$$1 != 2 { print "cmd/dump -l and test/INDEX disagree on " $$2; bad = 1 } \
	         END { exit bad }'
	cd cmd && grep -oE '[0-9a-f]{64}  tweetnacl\.[ch]' VENDOR | sha256sum -c
	{ grep -oE '^ +crypto_[a-z_]+' cmd/VENDOR | tr -d ' ' | LC_ALL=C sort -u; \
	  nm cmd/dump.o | sed -n 's/.* U \(crypto_[a-z_0-9]*\)/\1/p' \
	    | sed 's/_\(ed25519\|curve25519\)_tweet//' | LC_ALL=C sort -u; } \
	  | LC_ALL=C sort | uniq -c \
	  | awk '$$1 != 2 { print "cmd/VENDOR and cmd/dump.o disagree on " $$2; bad = 1 } \
	         END { exit bad }'
	tools/gen
	tools/cite

clean:
	rm -f cmd/dump $(OBJ)

help:
	@echo 'make            build cmd/dump'
	@echo 'make check      run every vector against cmd/dump'
	@echo 'make gen        regenerate the vectors; needs Python and the checkout'
	@echo 'make verify     check, then regenerate and check every citation'
	@echo 'make clean      remove cmd/dump and the objects'
	@echo
	@echo 'DUMP=./mine cmd/check       check another implementation'
	@echo 'DUMP=./mine ENCODE=no ...   skip the round trip'
	@echo 'cmd/dump -l                 list the kinds a decoder can be asked for'

.PHONY: check gen verify clean help
