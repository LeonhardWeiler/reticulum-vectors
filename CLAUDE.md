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
point. Three vectors turn on the difference; tools/gen refuses to run
under the other backend.

---

# Redundancy Rules

Upstream already provides:

    docs/source/understanding.rst   protocol concepts, mechanics, rationale
    tests/hashes.py                 SHA-256 and SHA-512 correctness
    tests/identity.py               5 key vectors, 1 signature, 1 token decrypt
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
                                    tests/link.py:113#dest.hash
    machine-readable vectors        upstream vectors are Python literals

If a proposed artifact does not fall in the second list, it does not
belong in the corpus.

---

# Determinism

Most Reticulum objects cannot be produced twice.

    deterministic     identity keys, name hash, destination hash, signature
    announce          random_hash = 5 random bytes || 5 bytes unix time
    encrypted packet  ephemeral X25519 key, random IV
    link handshake    ephemeral keys

That is not what the class turns on. The class says whether expect is
total:

    determinism: encode    expect holds every byte of raw
    determinism: decode    it does not

Randomness is no obstacle. expect records what the random bytes came
out as, so raw follows from expect even when nothing can produce those
bytes a second time. Where raw carries an input that is not the object
itself, the recipient key of an encrypted packet or the link request a
proof answers, expect echoes it as a field and stays total.

The class is enforced, not asserted, and it is not declared by hand.
tools/gen derives it, since the vector either has the fields or does
not, and cmd/check rebuilds raw from expect for every encode-class
vector and diffs the result. A declaration that no program reads is
decoration, and one written by hand is a claim that can be wrong.

cmd/check tests the other direction too, and has to. gen derives the
class and a consumer does not run gen, so for the reader who has only
test/, cmd/ and doc/, decode was the one field in meta whose error
skips a check rather than causing one. A decode-class vector whose
expect rebuilds raw is now a failure.

Only two things put a vector in the decode class: expect records a
field by digest rather than by content, or the object broke a rule and
has no fields at all. Ten of the ninety are of that class.

The corpus proves the read direction with expect and the write
direction with the round trip. An implementation that decodes every
vector and emits packets no reference will accept still fails
cmd/check.

---

# Repository Structure

    reticulum-vectors/

        README
        CONFORMANCE     what independent implementations do with the corpus

        doc/
            fields          every name expect can carry, and where
            identity        key composition, identity hash
            destination     app name, aspects, name hash, destination hash
            packet          header, flags, addresses, context byte
            announce        payload layout, signed material, validation
            encryption      key agreement, derivation, token, padding
            link            request, proof, link id, derivation, contexts
            resource        parts, advertisement, requests, cancels, proof
            harness         how to check an implementation, in one page

        test/
            identity/       public key to identity hash
            keyset/         private key to public key
            destination/    name to destination hash
            signature/      Ed25519 as Identity.sign applies it
            sign/           private key and message to the signature
            announce/       whole packets, unencrypted
            plain/          payload handed through unencrypted
            pathrequest/    the payload a transport node reads
            encrypted/      whole packets, decrypted to plaintext
            group/          a token under a key nobody negotiates
            linkrequest/    link requests, and the link id they open
            linkproof/      link request proofs, signature verified
            linkdata/       packets on an established link, resources
                            among them
            proof/          delivery proofs, both accepted forms
            resourceproof/  a proof over a resource, which signs nothing
            ifac/           a packet inside an interface access frame

        cmd/
            dump.c          decode one object, print its fields
            sha256.c        written out, not vendored
            hmac.c          HMAC-SHA256 and HKDF, written out
            aes256.c        AES-256-CBC decryption, written out
            tweetnacl.[ch]  vendored unmodified, see cmd/VENDOR
            VENDOR          origin and hashes; make verify checks them
            check           shell script: dump | diff - expect

        conformance/
            README          what a result covers, and what it does not
            <impl>/         one harness per implementation measured

        tools/
            gen             python, generates vectors against the pinned RNS
            cite            python, checks every RNS line citation

Nine documents. One C program. One shell script. Two tools that are
not part of the contract, because a consumer runs neither.

---

## doc/

Each document contains byte layouts, derivation rules, and invariants.

Nothing else. No motivation, no rationale, no examples of use. Those
exist upstream.

A document that could be summarised as "explains what X is for" is
redundant and is deleted.

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
run against a test/ that holds anything else. A corpus that counts what
it finds and calls the total a result cannot tell a complete copy from
a pruned one; both report zero failures.

meta format:

    source        python-rns 1.4.2 (b48b96e6)
    determinism   encode
    purpose       announce with ratchet, no app_data

All three are required. cmd/check rejects a vector that omits one or
names an unknown class.

Three fields, not five. The kind is the directory the vector is filed
under; recording it in meta as well bought one rule to keep the two
agreeing and one way for them to disagree. A date of generation was
checked for presence and never for content, and tools/gen had to carry
it forward by hand so that make verify would not fail on any day after
the corpus was written. The pin in source is the provenance.

Adopted vectors record their origin instead:

    source        python-rns tests/identity.py:13#fixed_keys (b48b96e6)

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

---

## cmd/

`dump` is the only compiled program. It decodes one object and prints
its fields in the format used by `expect`. With `-e` it runs the other
way, rebuilding raw from expect, which is how the encode class is
enforced.

`check` is a shell script. For each vector it validates meta, then runs

    dump <kind> <raw>      | diff - expect
    dump -e <kind> expect  | diff - raw     (encode class only)
    dump -e <kind> expect                   (decode class: must fail)

Before the first vector it refuses a test/ that disagrees with
test/INDEX, a field name that doc/fields does not carry or that no
vector does, and an optional field with only one of its two cases on
file. Each of those was a sentence somewhere before it was a check.

There is no separate validator binary. A checker that shares a decoder
with the dumper would be one program written twice.

Note that the exit status of a pipeline is the status of its last
command. A diff whose verdict is read from something downstream of it
reports nothing; read the output instead.

`dump` is the second implementation of the wire format. That is its
purpose: it proves the vectors are usable without Python.

---

## tools/

`gen` is Python. It imports the pinned RNS and writes vector
directories including meta. It never edits an existing vector in place;
regeneration produces a new directory or an explicit diff.

`cite` is Python. doc/ and the programs name the reference by line, in
the form `RNS/Packet.py:190#Packet.ANNOUNCE`, and nothing else reads
those numbers, so they drift. `cite` resolves every one against the checkout
and fails on any that no longer names a line holding what it is cited
for. Twelve had already slid before it existed.

Where it looks is `git ls-files` and not a list of its own. A list of
where to check fails in the direction that says nothing: the file
nobody added to it is not reported, it is simply never read.

Neither is shipped as part of the corpus contract. They are the way
vectors are produced and kept honest, not the way they are consumed.
`make verify` runs both, and needs Python and the checkout. `make
check` runs neither and needs a C compiler.

### Nothing has to be started, and that is two rules

    A consumer of the corpus starts nothing.
    gen starts no Reticulum instance.

The first is the artifact. The second is a convenience, and it does not
inherit the first one's authority.

The second is worth keeping: it is why regeneration is deterministic and
why `make verify` can insist that not one byte changed. It is paid for.
`gen` is larger than `dump`, and it stands in for the instance it does
not start in eleven places, among them `Transport.owner`, `Packet.send`,
`Reticulum.storagepath`, `Reticulum.transport_enabled` and both
randomness sources. Every one of those
is an assumption about what the reference would have done. One has
already been wrong: pinning `os.urandom` did not reach the openssl
backend, and the ratchet vectors changed on every run while doc/announce
claimed they did not.

The commit is part of the pin and so is the working tree. `rev-parse
HEAD` names the commit and says nothing about edits on top of it, and a
vector generated from an edited checkout claims the pin as its source,
which is the strongest provenance the format has. `gen` refuses a
checkout `git status --porcelain` reports anything for.

So the standing rule is not "never start it" but:

    raw is what the reference produced.

Where a value in raw was composed by gen out of the reference's own
functions, rather than captured from the reference running them, doc/
says so at that vector. There is no such value left. The one there was,
the interface key of test/ifac, is now derived in expect from the two
configured strings that raw carries, so `dump` derives it a second time
and `check` diffs the two. A composed value nothing can check is worth
one line of doc/; a derived value two implementations agree on is worth
more, and is the better answer wherever it is available.

There is one case between the two, and it is written down rather than
argued away. test/group/zero-padding needs a token the reference cannot
be asked for: `PKCS7.pad` writes 1 to 16, and the corpus needs a
padding length of nought, which `PKCS7.unpad` accepts and no encoder
produces. So `pad` is replaced by the identity for that one call and
everything else runs, which makes raw the reference's own
`Token.encrypt` output rather than a token assembled from primitives.
The vector's meta names the replaced function, and doc/encryption says
why the vector exists at all.

The rule this obeys is not "gen replaces nothing". `pinned()` already
replaces the clock, `os.urandom`, `get_random_hash`,
`_generate_ratchet` and three key classes, and every byte of every
ratchet vector comes out of those. The rule is that each replacement is
named where a reader of the corpus will meet it.

`expect` is a different matter and is meant to be gen's own reading of
raw, asserted against RNS wherever RNS exposes something to assert
against, and checked again by `dump`, which shares no code with it.

Nothing enforces this. No program can tell a composed value from a
captured one, which is exactly why it is written down. `conformance/`
carries the same obligation for foreign code and calls it called,
transcribed and absent; this is that rule turned on the generator.

---

# Cryptography in C

Vectors drive the dependency, not the other way around.

    milestone 1          SHA-256, Ed25519 verify, SHA-512, X25519 base
    milestone 2          adds HMAC-SHA256, HKDF, AES-256-CBC, X25519 exchange
    milestone 3          adds nothing
    test/sign            adds Ed25519 sign

Announces are not encrypted (RNS/Packet.py:190#Packet.ANNOUNCE), so
milestone 1 needed no symmetric cryptography at all.

Ed25519 signing arrived with test/sign and cost nothing to vendor:
tweetnacl ships crypto_sign beside the crypto_sign_open the corpus was
already linking, and dump was already deriving a public key from a seed
through crypto_sign_keypair.

Only what a vector requires is written or vendored. AES is decryption
only and 256-bit only, because every token in the corpus is one the
reference produced from a 64-byte derived key.

The 128-bit mode was expected to arrive with links. It did not. Only
MODE_AES256_CBC is in ENABLED_MODES at this pin
(RNS/Link.py:133#ENABLED_MODES), and signalling_bytes raises on any
other, so no link the reference establishes uses it. AES-128 waits for
a vector that needs it, and none does.

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

---

# Before Adding Anything

Ask, in order:

    Does upstream already provide this?
    Would an independent implementation fail without it?
    Can a file replace a program?
    Can a shell script replace a binary?
    Is the determinism class honest?

If the first answer is yes, stop.
