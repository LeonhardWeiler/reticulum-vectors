# Project: Reticulum Vector Corpus

## What this is

README says what the corpus is, what the pin is and why the backend is
part of it. It is not repeated here; a rule written twice is a rule that
can disagree with itself.

What this file adds is how to work on the repository. It is read by
whoever changes it, not by whoever uses it.

One word is used throughout and is defined here: a consumer is any
implementation that wants to know whether it agrees with the reference.
Which implementation that is is never this repository's concern, and
consumer is the word for all of them.

---

# Redundancy Rules

Upstream already provides:

    docs/source/understanding.rst   protocol concepts, mechanics, rationale
    tests/hashes.py                 SHA-256 and SHA-512 correctness
    tests/identity.py               key vectors, a signature, a token decrypt
    tests/link.py                   integration tests, Python against Python
    tests/channel.py                unit tests of Python internals

Rules:

    A statement that appears in understanding.rst is not restated here.
    Link to it.

    A vector that exists upstream is adopted verbatim with attribution.
    It is not re-derived.

    Primitives that every language already provides are not tested.
    No SHA-256 or SHA-512 vectors.

    Tests that require a running Reticulum instance are not ported.
    They assert nothing about bytes, which is the only reason.

What upstream does not provide, and this corpus does:

    raw packet bytes                none exist upstream
    announce byte layout            none exist upstream
    destination hash derivation     one incidental case,
                                    tests/link.py#dest.hash
    machine-readable vectors        upstream vectors are Python literals

If a proposed artifact does not fall in the second list, it does not
belong in the corpus.

---

# Determinism

What the two classes mean, that the class turns on whether expect is
total and not on whether the bytes can be produced twice, and which two
things put a vector in the decode class: README, section "Vector
format".

What that section does not say, because it is a rule about this
repository and not about a vector:

The class is derived by tools/gen from which rule was broken, never
declared by hand, and it is enforced in both directions. cmd/check
rebuilds raw from expect for every encode-class vector and diffs the
result, and fails a decode-class vector whose expect rebuilds raw. A
consumer does not run gen, so without the second test decode would be
the one field in meta whose error skips a check rather than causing one.

The corpus proves the read direction with expect and the write
direction with the round trip. An implementation that decodes every
vector and emits packets no reference will accept still fails
cmd/check.

---

# Repository Structure

README, section "Layout", lists the directories and says which three a
consumer needs. What it does not say:

One C program. One shell script. One tool that is not part of the
contract, because a consumer does not run it.

The two workflows under .github/ check this repository. They promise
nothing to anyone else.

Nothing here is published as an interface. There was a composite action
for one day, so that a consumer's workflow could be three lines. Three
lines is not what it cost: it is a versioned surface with two inputs, a
tag that has to be moved, and one CI vendor baked in, all wrapping two
commands that were already the whole job.

What replaced it is `conformance/example/vectors.yml`, a file to copy
rather than a thing to depend on, beside the example harness it runs.
It is copied, not linked, so nothing here can change under a consumer,
and doc/harness points at it rather than printing it a second time.

---

## doc/

Each document contains byte layouts, derivation rules, and invariants.

Nothing else. No motivation, no rationale, no examples of use. Those
exist upstream.

A document that could be summarised as "explains what X is for" is
redundant and is deleted.

No program parses a document. What a document says is kept true by
writing it so that it stays true.

---

## test/

The three files, the naming, test/INDEX, the three meta fields and the
rule that every value is hex, a number or a keyword: README, section
"Vector format". When writing a vector rather than reading one, two
more rules apply.

An adopted vector records where it came from in source, in place of the
pin:

    source        python-rns tests/identity.py#fixed_keys (b48b96e6)

A rejection names the rule broken and the numbers behind it, so that
two decoders cannot agree by accident while failing for different
reasons. Where the number is already in the output it is not repeated:

    invalid            short-payload
    payload_length     147
    minimum_length     148

---

## cmd/

`dump` is the only compiled program, and it is the second
implementation of the wire format. That is its purpose: it proves the
vectors are usable without Python. What it prints and what `-e` does are
in README.

The encode direction is a table of field names, one row per kind,
because in that direction an absent field is `-` and contributes no
bytes. It is the encoders' own table and not one shared with the
decoders. A shared one would have to say that a ratchet is present when
the context flag is set, that signalling is present at one payload
length and not another, and that a keepalive on a link has no token at
all. Those are the decoders, expressed less directly.

`check` is a shell script. For each vector it validates meta, then runs

    dump <kind> <raw>      | diff - expect
    dump -e <kind> expect  | diff - raw     (encode class only)
    dump -e <kind> expect                   (decode class: must fail)

Before the first vector it refuses a test/ that disagrees with
test/INDEX.

Whether an optional field has both of its cases on file is a statement
about the corpus and not about a decoder, so tools/gen refuses that,
where the missing vector can be written.

There is no separate validator binary. A checker that shares a decoder
with the dumper would be one program written twice.

Note that the exit status of a pipeline is the status of its last
command. A diff whose verdict is read from something downstream of it
reports nothing; read the output instead. This applies in the workflow
too, where a step runs under `bash -e` without `pipefail`.

---

## tools/

`gen` is Python. It imports the pinned RNS and writes vector
directories including meta. It never edits an existing vector in place;
regeneration produces a new directory or an explicit diff.

It is not shipped as part of the corpus contract. `make verify` runs
it and needs Python and the checkout; `make check` does not, and needs
a C compiler.

doc/, the programs and the meta files name the reference by symbol:

    RNS/Packet.py#Packet.ANNOUNCE

There is no line number, and that is the whole rule: the anchor is the
name to grep for, and nothing in a citation can go stale while the pin
holds. When the pin moves and a symbol is gone, the vectors are
regenerated anyway.

Two tools were deleted for one rule, and it is the rule for any tool
proposed here:

    A tool checks bytes. Prose that has to be checked is prose that is
    written wrong; change the format, do not write the parser.

`counts` resolved the totals the prose stated against the corpus,
through a table of English phrasings, and needed an exemption for its
own source. `cite` resolved a line number that carried nothing.
Deleting the number deleted the tool.

### Nothing has to be started, and that is two rules

    A consumer of the corpus starts nothing.
    gen starts no Reticulum instance.

The first is the artifact. The second is a convenience and does not
inherit the first one's authority. It is why regeneration is
deterministic and why `make verify` can insist that not one byte
changed.

What stands in for the instance is `stub_transport`, and it is the
whole of it: `Transport.owner`, `register_destination`,
`_remember_ratchet`, and the four `Reticulum` attributes a constructor
would have set. Everything around it is a different job.
`pinned` replaces the clock, both randomness sources and three key
classes, and would be needed against a running instance too, because a
running instance draws the same random bytes. `captured`, `inline_threads`
and `handler_reads` observe what the reference did with the bytes, which
a running instance makes harder rather than easier.

Every one of those is an assumption about what the reference would have
done, and one has been wrong — pinning `os.urandom` did not reach the
openssl backend, and the ratchet vectors changed on every run.

The commit is part of the pin and so is the working tree, so `gen`
refuses a checkout `git status --porcelain` reports anything for. A
vector generated from an edited checkout would claim the pin as its
source, which is the strongest provenance the format has.

The standing rule is therefore not "never start it" but:

    raw is what the reference produced.

No value in raw is composed by gen out of the reference's own
functions. The one that was, the interface key of test/ifac, is derived
in expect from the two configured strings raw carries, so `dump`
derives it again and `check` diffs the two.

Two cases sit between the two and are written down rather than argued
away. Each needs a padding `PKCS7.unpad` accepts and `PKCS7.pad` never
writes, so `pad` is replaced by the identity for the one call that
packs them: a length of nought, and a token with no ciphertext at all.
raw is still the reference's own `Token.encrypt` output, and
doc/encryption names both. The rule is not "gen replaces nothing" —
`pinned()` replaces the clock, three key classes and both randomness
sources — but that each replacement is named where a reader of the
corpus will meet it. Those two are named in their own meta.

The second of them is why a reason on the list below is read again
rather than counted on: it was on it, as a token the reference could
not be asked for, and the replacement that had already been made for
the first was what took it off.

`expect` is a different matter. It is what the reference says about
its own bytes wherever RNS exposes the field, and gen's reading of raw
where it does not, and `dump` reads raw again sharing no code with
either.

Nothing enforces this. No program can tell a composed value from a
captured one, which is exactly why it is written down. `conformance/`
carries the same obligation for foreign code and calls it called,
transcribed and absent; this is that rule turned on the generator.

---

# Cryptography in C

Vectors drive the dependency, not the other way around. Only what a
vector requires is written or vendored. README lists which is which.

AES is decryption only. It is both key lengths since test/group/aes128,
and that vector is what bought the second one: the rule is that the
vector comes first and the code follows it, not that the code is kept
small.

Nothing on a link reaches AES-128. Only MODE_AES256_CBC is in
ENABLED_MODES at this pin (RNS/Link.py#ENABLED_MODES) and
signalling_bytes raises on any other. The one door to the mode is a
group key a human configured at 32 bytes, because every other token key
in the corpus is 64 bytes the reference derived.

---

# Upstream License

The two added restrictions are in README and in LICENSE. What follows
from them for work done here:

Deriving documentation and generating vectors is unaffected. Copying
code or documentation text requires attribution. The upstream checkout
is not committed; it is pinned and fetched.

---

# Writing Style

Short sentences. Precise definitions. Concrete byte offsets.

Prefer:

    The flags byte occupies offset 0. Bit 7 is reserved and set to zero.

Avoid:

    The packet framework provides a flexible mechanism...

Plain text. Fixed-width tables. No JSON, no YAML, no test framework.

A comment says what the code does and why it does it that way now. What
it did before is in git log.

No comment stands above a function definition, in cmd/dump.c or in
tools/gen. What such a comment said about the bytes belongs in doc/,
and what it said about the code goes inside the function, beside the
line it is about. The explanation at the top of a file is not one of
these and stays.

---

# Before Adding Anything

Ask, in order:

    Does upstream already provide this?
    Would an independent implementation fail without it?
    Can the reference be made to produce the bytes?
    Can a file replace a program?
    Can a shell script replace a binary?
    Is the determinism class honest?

If the first answer is yes, stop.

The third has been asked and answered for four cases, and doc/packet,
section "What has no vector", holds the four with the reason each one
cannot be produced. Read it before proposing a vector for any of them.

Three have left that list since it was written, and all three left the
same way: the reason was read again and did not hold. One turned out to
be a truncation like any other. The second, a resource payload of the
wrong msgpack shape, was excluded because the layers above the packet
do not build such a payload, which is not the question the third asks:
what a link carries is chosen by the sender, and four vectors already
handed a chosen plaintext to Link.encrypt. It now has six vectors, and
it has found a defect in cmd/dump twice. The third, a token of 48
bytes, was excluded because `PKCS7.pad` writes no such token, by which
time test/group/zero-padding had been on file for ten days with `pad`
replaced by the identity. That is the argument for writing the list
rather than carrying it in someone's head, and for reading a reason
rather than counting on it.

Where a new kind lands, measured on the three commits that added one
(f613b11, 403b6b8, ca34569), in lines outside test/:

    tools/gen                        67 - 343
    doc/, one document plus fields   59 - 275
    conformance/, six harnesses           257
    cmd/dump.c                       51 - 189
    CONFORMANCE                      13 -  59

Two things in that order are worth knowing before starting. The C
decoder is the cheapest part and the generator the dearest, because gen
builds the object with RNS and reads it back independently and dump only
reads: the doubled cost is the second reading, which is the product.

And a kind costs every harness in conformance/, seven of them today in
six languages, or it costs the denominator: a harness exits 77 for a
kind it does not know, so the new vectors are skipped for everyone and
every row in CONFORMANCE counts against a larger number. Either is
defensible and cbdb8d3 already chose the second once. Choose it
deliberately. The row above is what six harnesses cost the last time
the first was chosen.
