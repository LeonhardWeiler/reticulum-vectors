# Project: Reticulum Vector Corpus

## What this is

Two repositories, built in order:

    reticulum-vectors/    verified Reticulum protocol data as files
    reticulum-haskell/    a Reticulum implementation in Haskell (later)

The corpus comes first. The implementation consumes it.

The corpus records what Python RNS actually puts on the wire, in a form
that can be checked without running Python.

It is not a specification. It does not define correct behaviour. It
records observed behaviour of one implementation at one version.

Reference implementation pin:

    python-rns 1.4.2, commit b48b96e6, openssl backend

Every vector records this pin. When the pin moves, vectors are
regenerated and differences are examined, not silently accepted.

The backend belongs in the pin. python-rns ships two curve
implementations and picks one at import time by what is installed, and
they disagree on a non-canonical Ed25519 S and on a low-order X25519
point. Vectors turn on the difference; tools/gen refuses to run under
the other backend. doc/identity and doc/encryption name them.

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

Most Reticulum objects cannot be produced twice: an announce carries a
random hash, an encrypted packet an ephemeral key and a random IV, a
link handshake ephemeral keys.

That is not what the class turns on. The class says whether expect is
total:

    determinism: encode    expect holds every byte of raw
    determinism: decode    it does not

Randomness is no obstacle. expect records what the random bytes came
out as, so raw follows from expect even when nothing can produce those
bytes a second time. Where raw carries an input that is not the object
itself — the recipient key of an encrypted packet, the link request a
proof answers — expect echoes it as a field and stays total.

Only two things put a vector in the decode class: expect records a
field by digest rather than by content, or the object broke a rule and
the bytes it broke it on are therefore not printed. A broken rule is
not by itself the second case; test/linkdata holds four vectors that
are broken inside a plaintext the packet around them decoded whole, and
they rebuild.

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

    README, CONFORMANCE     what this is; what other implementations score
    doc/                    nine documents, byte layouts and derivations
    test/                   the vectors, one directory each, sixteen kinds
    cmd/                    dump.c and its cryptography; check, a shell script
    conformance/            one harness per implementation measured
    tools/gen               python, generates the vectors against the pinned RNS
    .github/                two workflows, which check this repository and
                            promise nothing to anyone else

One C program. One shell script. One tool that is not part of the
contract, because a consumer does not run it.

A consumer needs test/, doc/ and cmd/. conformance/ is the larger half
of a clone, needing Go, Rust, Node, Elixir and a C++ compiler between
its six harnesses, and README says so where it lists the layout.

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

One directory per vector, named after what it records rather than
numbered, so that inserting a case renumbers nothing and doc/ can refer
to one by name:

    test/announce/ratchet/

        meta      provenance and determinism class
        raw       the input, hex, one blob per line
        expect    field decomposition, byte-identical to what dump prints

test/INDEX names every vector, one per line, and cmd/check refuses to
run against a test/ that holds anything else.

meta has three fields, all required:

    source        python-rns 1.4.2 (b48b96e6)
    determinism   encode
    purpose       announce with ratchet, no app_data

The kind is the directory the vector is filed under and is not repeated
here. Adopted vectors record their origin in source instead:

    source        python-rns tests/identity.py#fixed_keys (b48b96e6)

Every value in expect is hex, a decimal number, or a keyword from a
fixed set. Byte strings are always hex, names included: printed as
text, a newline inside one would end the line early and let a vector
forge or hide a field.

Negative vectors are stored the same way. A failure names the rule
broken and the numbers behind it, so that two decoders cannot agree by
accident while failing for different reasons:

    invalid            short-payload
    payload_length     147
    minimum_length     148

Where the number is already in the output the rejection does not repeat
it.

---

## cmd/

`dump` is the only compiled program. It decodes one object and prints
its fields in the format used by `expect`. With `-e` it runs the other
way, rebuilding raw from expect, which is how the encode class is
enforced. It is the second implementation of the wire format, and that
is its purpose: it proves the vectors are usable without Python.

`check` is a shell script. For each vector it validates meta, then runs

    dump <kind> <raw>      | diff - expect
    dump -e <kind> expect  | diff - raw     (encode class only)
    dump -e <kind> expect                   (decode class: must fail)

Before the first vector it refuses a test/ that disagrees with
test/INDEX, and an optional field with only one of its two cases on
file. Both read the corpus.

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

One case sits between the two and is written down rather than argued
away: test/group/zero-padding needs a padding length of nought, which
`PKCS7.unpad` accepts and `PKCS7.pad` never writes, so `pad` is
replaced by the identity for that one call. raw is still the
reference's own `Token.encrypt` output. The rule is not "gen replaces
nothing" — `pinned()` replaces the clock, three key classes and both
randomness sources — but that each replacement is named where a reader
of the corpus will meet it. That one is named in the vector's meta.

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
vector requires is written or vendored.

SHA-256, HMAC-SHA256, HKDF and AES-256-CBC are written out; tweetnacl
is vendored unmodified for Ed25519, SHA-512 and X25519.

AES is decryption only and 256-bit only, because every token in the
corpus is one the reference produced from a 64-byte derived key. Only
MODE_AES256_CBC is in ENABLED_MODES at this pin
(RNS/Link.py#ENABLED_MODES) and signalling_bytes raises on any other,
so no link the reference establishes uses AES-128. It waits for a
vector that needs it, and none does.

---

# Upstream License

Reticulum is licensed permissively with two added restrictions: no use
in systems intended to harm humans, and no use in AI or language model
training datasets.

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

---

# Before Adding Anything

Ask, in order:

    Does upstream already provide this?
    Would an independent implementation fail without it?
    Can a file replace a program?
    Can a shell script replace a binary?
    Is the determinism class honest?

If the first answer is yes, stop.
