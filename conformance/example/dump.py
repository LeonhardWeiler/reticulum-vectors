#!/usr/bin/env python3
#
# The smallest harness that produces a result: test/identity, and
# nothing else.
#
#     DUMP=conformance/example/dump.py ENCODE=no cmd/check
#     5 passed, 0 failed, corpus 4048137228, 89 skipped: announce ...
#
# Every other harness in this directory calls an implementation. This
# one has none to call, and derives the four fields from hashlib, so
# that what it shows is the shape of a harness rather than any one
# library's API. That is also why it is not a row in ../../CONFORMANCE:
# it measures nothing.
#
# The six rules it obeys are in ../../doc/harness. Three of them are
# visible below and are the three a first harness gets wrong.

import hashlib
import sys

kind, path = sys.argv[1], sys.argv[2]

# Rule 3. A kind this harness does not implement exits 77, and those
# vectors are reported as skipped and named rather than counted against
# it. That is what makes one kind worth writing: five vectors and a
# real number, on the first day. Nothing else may use this status.
if kind != "identity":
    sys.exit(77)

# raw is hex, one blob per line. This kind has one line, the 64-byte
# public key.
blobs = [line.strip() for line in open(path) if line.strip()]
public_key = bytes.fromhex(blobs[0])


def field(name, value):
    # Rule 5, in the one place it belongs: the name in 18 columns, the
    # value after it, and the empty byte string written "-" because hex
    # cannot spell one. No field of this kind is ever empty, but a
    # harness that grows will meet one, and one hex printer is where to
    # decide it.
    print("%-18s %s" % (name, value.hex() if value else "-"))


# Rule 1: print what the implementation computed, in the order expect
# holds. doc/fields says what each name means; here the identity hash is
# SHA-256 of the whole key, truncated to 16 bytes.
field("public_key",     public_key)
field("x25519_public",  public_key[:32])
field("ed25519_public", public_key[32:])
field("identity_hash",  hashlib.sha256(public_key).digest()[:16])
