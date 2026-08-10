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
# checkout; check alone does not.
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
# largest stretch of prose in the repository that restates bytes. The
# block is folded to fit the page, so the layout is stripped from both
# sides and what is left has to be the same bytes in the same order.
#
# Nothing here knows how the block wraps, which is the point: it was an
# unfolder once, twenty-five lines that had to be told which
# continuation joins with a space and which with nothing, and the
# README had to be indented to suit it. Ignoring whitespace is the same
# check without the rule.
#
# The block is every indented line from "    meta" to the paragraph
# after it, less the three section names, which are not in any file.
#
# Not in cmd/check: that is the consumer contract, and a consumer needs
# test/, doc/ and cmd/ and no README.
verify: check
	{ sed -n '/^    meta$$/,/^[^ ]/p' README | grep '^ ' | grep -v '^    [a-z]*$$'; \
	  echo =; \
	  cat test/pathrequest/tagged/meta test/pathrequest/tagged/raw \
	      test/pathrequest/tagged/expect; } \
	| tr -d ' \n' \
	| awk -F= '$$1 != $$2 { print "README and test/pathrequest/tagged/ hold different bytes"; \
	                        bad = 1 } END { exit bad }'
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
