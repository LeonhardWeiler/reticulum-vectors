/* dump - decode one Reticulum object and print its fields.
 *
 *	dump kind rawfile		decode raw, print fields
 *	dump -e kind expectfile		rebuild raw from fields
 *
 * dump is a second implementation of the wire format, independent of
 * python-rns. That is its purpose. It deliberately shares no code with
 * the generator.
 *
 * Every value it prints is hex, a decimal number, or a keyword from a
 * fixed set. A destination name is arbitrary bytes, so printing it as
 * text would let a newline in an aspect forge or hide a field. */

#include "aes256.h"
#include "hmac.h"
#include "sha256.h"
#include "tweetnacl.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Each bound is the largest thing the format can hold, not one number
 * applied everywhere. A packet is bounded by the 500-byte MTU; the
 * largest input in the corpus is the 950-byte message of the adopted
 * signature vector. No vector carries more than three blobs or more
 * than 29 fields. */
#define MAXBLOB   2048
#define MAXBLOBS  4
#define MAXFIELDS 32
#define FIELDW    18

#define ADDRLEN      16
#define KEYHALF      32
#define KEYSIZE      64
#define NAMEHASHLEN  10
#define RANDHASHLEN  10
#define SIGLEN       64
#define RATCHETLEN   32
#define IVLEN        16
#define MACLEN       32
#define TOKEN_OVERHEAD (IVLEN + MACLEN)   /* RNS/Cryptography/Token.py:50 */
#define DERIVEDLEN   64
#define MAX_HOPS     128	/* RNS.Transport.PATHFINDER_M */
#define ECPUBSIZE    64		/* RNS/Link.py:70 */
#define SIGNALLEN    3		/* RNS/Link.py:80 */
#define MTU_BYTEMASK 0x1fffff	/* RNS/Link.py:144 */
#define MODE_DEFAULT 0x01	/* RNS/Link.py:134 */

static const char *argv0;

static void fatal(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s: ", argv0);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(1);
}

static void field(const char *name, const char *fmt, ...)
{
	va_list ap;

	printf("%-*s ", FIELDW, name);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
}

/* The empty byte string is written "-", not as an empty value. A name
 * followed by nothing is a line with a trailing space: it cannot be
 * told from a truncated line, and cmd/check rejects it. Every optional
 * field already spells absence that way, and a destination aspect may
 * legitimately be empty. See doc/destination. */
static void field_hex(const char *name, const uint8_t *p, size_t n)
{
	size_t i;

	if (n == 0) {
		field(name, "-");
		return;
	}

	printf("%-*s ", FIELDW, name);
	for (i = 0; i < n; i++)
		printf("%02x", p[i]);
	putchar('\n');
}

struct blob {
	uint8_t  data[MAXBLOB];
	size_t   len;
	int      absent;	/* the line was "-" */
};

/* An input blob is echoed as a field so that expect holds every byte of
 * raw and the encode direction has something to rebuild from. */
static void field_blob(const char *name, const struct blob *b)
{
	if (b->absent)
		field(name, "-");
	else
		field_hex(name, b->data, b->len);
}

static int unhex(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static void decode_hex(struct blob *b, const char *s, size_t len, const char *where)
{
	size_t i;

	if (len % 2 != 0)
		fatal("%s: odd hex length", where);
	if (len / 2 > MAXBLOB)
		fatal("%s: %zu bytes exceeds %d", where, len / 2, MAXBLOB);

	b->len = 0;
	for (i = 0; i < len; i += 2) {
		int hi = unhex(s[i]), lo = unhex(s[i+1]);
		if (hi < 0 || lo < 0)
			fatal("%s: bad hex", where);
		b->data[b->len++] = (uint8_t)(hi << 4 | lo);
	}
}

/* Read one line, rejecting any that did not fit. A silently split line
 * would decode as two blobs and quietly change what is being tested. */
static int readline(FILE *f, char *buf, size_t size, const char *path, int n)
{
	size_t len;

	if (fgets(buf, (int)size, f) == NULL)
		return 0;

	len = strlen(buf);
	if (len == size - 1 && buf[len-1] != '\n')
		fatal("%s: line %d longer than %zu bytes", path, n, size - 2);

	while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r'))
		buf[--len] = '\0';
	return 1;
}

static int readraw(const char *path, struct blob *out, int max)
{
	FILE *f;
	char line[MAXBLOB*2 + 4];
	int n = 0;

	if ((f = fopen(path, "r")) == NULL)
		fatal("cannot open %s", path);

	while (readline(f, line, sizeof line, path, n + 1)) {
		struct blob *b;
		size_t len = strlen(line);

		if (len == 0)
			continue;
		if (n == max)
			fatal("%s: more than %d lines", path, max);

		b = &out[n++];
		b->len = 0;
		b->absent = 0;

		if (len == 1 && line[0] == '-') {
			b->absent = 1;
			continue;
		}
		decode_hex(b, line, len, path);
	}

	fclose(f);
	return n;
}

/* No value ever contains a space, so splitting on the first one is
 * exact and needs no quoting rule. */
struct kv {
	char name[32];
	char value[MAXBLOB*2 + 2];
};

static int readexpect(const char *path, struct kv *out, int max)
{
	FILE *f;
	char line[MAXBLOB*2 + 64];
	int n = 0;

	if ((f = fopen(path, "r")) == NULL)
		fatal("cannot open %s", path);

	while (readline(f, line, sizeof line, path, n + 1)) {
		char *value;
		size_t namelen;

		if (line[0] == '\0')
			continue;
		if (n == max)
			fatal("%s: more than %d fields", path, max);

		value = line;
		while (*value != '\0' && *value != ' ')
			value++;
		namelen = (size_t)(value - line);
		while (*value == ' ')
			value++;

		if (namelen == 0 || namelen >= sizeof out[n].name)
			fatal("%s: unusable field name on line %d", path, n + 1);
		if (strlen(value) >= sizeof out[n].value)
			fatal("%s: value too long on line %d", path, n + 1);

		memcpy(out[n].name, line, namelen);
		out[n].name[namelen] = '\0';
		strcpy(out[n].value, value);
		n++;
	}

	fclose(f);
	return n;
}

static const char *lookup(struct kv *fields, int n, const char *name)
{
	int i;

	for (i = 0; i < n; i++)
		if (strcmp(fields[i].name, name) == 0)
			return fields[i].value;
	fatal("no field named %s", name);
	return NULL;
}

/* tweetnacl leaves randombytes to the caller and declares it nowhere,
 * so the definition below carries its own prototype. dump has
 * no use for randomness; the one place tweetnacl reaches for it is
 * crypto_sign_keypair, which is how an Ed25519 public key is derived
 * from a given seed without editing the vendored source. Serving that
 * call a chosen seed keeps tweetnacl unmodified. Any other call is a
 * bug and stops the program. See VENDOR. */

static unsigned char rb_seed[32];
static int rb_armed;

void randombytes(unsigned char *x, unsigned long long n);

void randombytes(unsigned char *x, unsigned long long n)
{
	if (!rb_armed || n != 32)
		fatal("randombytes called outside seeded key derivation");
	memcpy(x, rb_seed, 32);
	rb_armed = 0;
}

static void ed25519_keypair(const uint8_t seed[32], uint8_t pk[32], uint8_t sk[64])
{
	memcpy(rb_seed, seed, 32);
	rb_armed = 1;
	crypto_sign_keypair(pk, sk);
}

static void ed25519_public(const uint8_t seed[32], uint8_t out[32])
{
	unsigned char sk[64];

	ed25519_keypair(seed, out, sk);
}

/* Ed25519 signing is deterministic, RFC 8032 section 5.1.6: the nonce
 * is derived from the key and the message and not drawn at random. A
 * signature is therefore something a vector can state. */
static void ed25519_sign(const uint8_t seed[32], const uint8_t *msg, size_t mlen,
                         uint8_t out[64])
{
	static unsigned char sm[MAXBLOB + 64];
	unsigned char pk[32], sk[64];
	unsigned long long smlen;

	if (mlen > MAXBLOB)
		fatal("message of %zu bytes exceeds %d", mlen, MAXBLOB);

	ed25519_keypair(seed, pk, sk);
	crypto_sign(sm, &smlen, msg, (unsigned long long)mlen, sk);
	memcpy(out, sm, 64);
}

/* The group order L, little endian. RFC 8032 section 5.1. */
static const uint8_t ed25519_L[32] = {
	0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,
	0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,
};

/* A signature is R || S with S a scalar, and RFC 8032 section 5.1.7
 * admits only S < L. Adding L to S yields a second encoding of the same
 * signature, which the pinned backend rejects and tweetnacl accepts:
 * crypto_sign_open reduces S rather than refusing it. The check belongs
 * here rather than in the vendored file, which is not edited.
 *
 * Without it dump reports signature_valid yes for an announce python-rns
 * drops. See doc/identity, section Canonical signatures. */
static int scalar_canonical(const uint8_t s[32])
{
	int i;

	for (i = 31; i >= 0; i--) {
		if (s[i] < ed25519_L[i]) return 1;
		if (s[i] > ed25519_L[i]) return 0;
	}
	return 0;			/* S == L is not canonical either */
}

static int ed25519_verify(const uint8_t pk[32], const uint8_t sig[64],
                          const uint8_t *msg, size_t mlen)
{
	static unsigned char sm[MAXBLOB + 64], m[MAXBLOB + 64];
	unsigned long long got;

	if (mlen > MAXBLOB)
		fatal("message of %zu bytes exceeds %d", mlen, MAXBLOB);

	if (!scalar_canonical(sig + 32))
		return 0;

	memcpy(sm, sig, 64);
	memcpy(sm + 64, msg, mlen);

	return crypto_sign_open(m, &got, sm, (unsigned long long)mlen + 64, pk) == 0;
}

/* X25519 against a point of small order yields an all-zero secret. The
 * pinned backend raises rather than returning it; tweetnacl returns it
 * and says nothing. A packet built that way has a key every reader of
 * the announce can compute, so the two behaviours are not equivalent.
 *
 * Returns 0 when no usable secret exists. See doc/encryption, section
 * Contributory behaviour. */
static int x25519_shared(uint8_t out[KEYHALF], const uint8_t scalar[KEYHALF],
                         const uint8_t peer[KEYHALF])
{
	size_t i;
	uint8_t acc = 0;

	crypto_scalarmult(out, scalar, peer);
	for (i = 0; i < KEYHALF; i++)
		acc |= out[i];

	return acc != 0;
}

static void truncated_hash(const uint8_t *p, size_t n, uint8_t *out, size_t take)
{
	uint8_t full[32];

	sha256(p, n, full);
	memcpy(out, full, take);
}

static void dump_identity(struct blob *b, int nblobs)
{
	uint8_t hash[ADDRLEN];

	if (nblobs != 1)
		fatal("identity: expected 1 blob, got %d", nblobs);
	if (b[0].len != KEYSIZE)
		fatal("identity: public key is %zu bytes, expected %d", b[0].len, KEYSIZE);

	truncated_hash(b[0].data, KEYSIZE, hash, ADDRLEN);

	field_hex("public_key",     b[0].data, KEYSIZE);
	field_hex("x25519_public",  b[0].data, KEYHALF);
	field_hex("ed25519_public", b[0].data + KEYHALF, KEYHALF);
	field_hex("identity_hash",  hash, ADDRLEN);
}

static void dump_keyset(struct blob *b, int nblobs)
{
	uint8_t pub[KEYSIZE];
	uint8_t hash[ADDRLEN];

	if (nblobs != 1)
		fatal("keyset: expected 1 blob, got %d", nblobs);
	if (b[0].len != KEYSIZE)
		fatal("keyset: private key is %zu bytes, expected %d", b[0].len, KEYSIZE);

	crypto_scalarmult_base(pub, b[0].data);
	ed25519_public(b[0].data + KEYHALF, pub + KEYHALF);
	truncated_hash(pub, KEYSIZE, hash, ADDRLEN);

	field_hex("private_key",     b[0].data, KEYSIZE);
	field_hex("x25519_private",  b[0].data, KEYHALF);
	field_hex("ed25519_private", b[0].data + KEYHALF, KEYHALF);
	field_hex("public_key",      pub, KEYSIZE);
	field_hex("x25519_public",   pub, KEYHALF);
	field_hex("ed25519_public",  pub + KEYHALF, KEYHALF);
	field_hex("identity_hash",   hash, ADDRLEN);
}

static void dump_destination(struct blob *b, int nblobs)
{
	uint8_t name_hash[NAMEHASHLEN];
	uint8_t material[NAMEHASHLEN + ADDRLEN];
	uint8_t dest_hash[ADDRLEN];
	size_t  matlen, start, i;

	if (nblobs != 2)
		fatal("destination: expected 2 blobs, got %d", nblobs);
	if (!b[1].absent && b[1].len != ADDRLEN)
		fatal("destination: identity hash is %zu bytes, expected %d", b[1].len, ADDRLEN);

	truncated_hash(b[0].data, b[0].len, name_hash, NAMEHASHLEN);

	memcpy(material, name_hash, NAMEHASHLEN);
	matlen = NAMEHASHLEN;
	if (!b[1].absent) {
		memcpy(material + matlen, b[1].data, ADDRLEN);
		matlen += ADDRLEN;
	}
	truncated_hash(material, matlen, dest_hash, ADDRLEN);

	field_hex("name", b[0].data, b[0].len);

	/* Split on dots. No component may contain a dot, so a plain scan
	 * is exact. */
	start = 0;
	for (i = 0; i <= b[0].len; i++) {
		if (i == b[0].len || b[0].data[i] == '.') {
			field_hex(start == 0 ? "app_name" : "aspect",
			          b[0].data + start, i - start);
			start = i + 1;
		}
	}

	field_hex("name_hash", name_hash, NAMEHASHLEN);
	if (b[1].absent)
		field("identity_hash", "-");
	else
		field_hex("identity_hash", b[1].data, ADDRLEN);
	field_hex("destination_hash", dest_hash, ADDRLEN);
}

static void dump_signature(struct blob *b, int nblobs)
{
	const uint8_t *ed_pub;
	uint8_t digest[32];

	if (nblobs != 3)
		fatal("signature: expected 3 blobs, got %d", nblobs);
	if (b[0].len != KEYSIZE)
		fatal("signature: public key is %zu bytes, expected %d", b[0].len, KEYSIZE);
	if (b[2].len != SIGLEN)
		fatal("signature: signature is %zu bytes, expected %d", b[2].len, SIGLEN);

	ed_pub = b[0].data + KEYHALF;
	sha256(b[1].data, b[1].len, digest);

	field_hex("ed25519_public", ed_pub, KEYHALF);
	field("message_length", "%zu", b[1].len);
	field_hex("message_sha256", digest, sizeof digest);
	field_hex("signature", b[2].data, b[2].len);
	field("valid", "%s",
	      ed25519_verify(ed_pub, b[2].data, b[1].data, b[1].len) ? "yes" : "no");
}

/* The other direction of test/signature: the signature is not given,
 * it is produced. An implementation that verifies correctly and signs
 * with a nonce of its own choosing passes every other vector here and
 * emits announces and link proofs nothing accepts. */
static void dump_sign(struct blob *b, int nblobs)
{
	uint8_t pub[KEYHALF], sig[SIGLEN], digest[32];

	if (nblobs != 2)
		fatal("sign: expected 2 blobs, got %d", nblobs);
	if (b[0].len != KEYSIZE)
		fatal("sign: private key is %zu bytes, expected %d", b[0].len, KEYSIZE);

	ed25519_public(b[0].data + KEYHALF, pub);
	ed25519_sign(b[0].data + KEYHALF, b[1].data, b[1].len, sig);
	sha256(b[1].data, b[1].len, digest);

	field_hex("private_key", b[0].data, KEYSIZE);
	field_hex("ed25519_private", b[0].data + KEYHALF, KEYHALF);
	field_hex("ed25519_public", pub, KEYHALF);
	field("message_length", "%zu", b[1].len);
	field_hex("message_sha256", digest, sizeof digest);
	field_hex("signature", sig, SIGLEN);
}

static const char *dest_types[]   = { "single", "group", "plain", "link" };
static const char *packet_types[] = { "data", "announce", "linkrequest", "proof" };
static const char *xport_types[]  = { "broadcast", "transport", "relay", "tunnel" };

enum reason { OK, SHORT_HEADER, HOP_LIMIT, SHORT_PAYLOAD };

struct header {
	unsigned flags, hops;
	unsigned header_type, context_flag, transport_type;
	unsigned destination_type, packet_type, context;
	const uint8_t *transport_id;		/* NULL for header 1 */
	const uint8_t *destination_hash;
	const uint8_t *payload;
	size_t payload_len;
};

struct announce {
	const uint8_t *public_key, *name_hash, *random_hash;
	const uint8_t *ratchet;			/* NULL when the flag is unset */
	const uint8_t *signature, *app_data;
	size_t app_data_len;
};

static enum reason parse_header(const uint8_t *raw, size_t len,
                                struct header *h, size_t *got, size_t *need)
{
	size_t header_len;

	if (len < 2) {
		*got = len; *need = 2;
		return SHORT_HEADER;
	}

	h->flags = raw[0];
	h->hops  = raw[1];

	h->header_type      = (h->flags & 0x40) >> 6;
	h->context_flag     = (h->flags & 0x20) >> 5;
	h->transport_type   = (h->flags & 0x10) >> 4;
	h->destination_type = (h->flags & 0x0c) >> 2;
	h->packet_type      = (h->flags & 0x03);

	if (h->hops >= MAX_HOPS) {
		*got = h->hops; *need = MAX_HOPS;
		return HOP_LIMIT;
	}

	header_len = 3 + ADDRLEN * (h->header_type + 1);
	if (len < header_len) {
		*got = len; *need = header_len;
		return SHORT_HEADER;
	}

	if (h->header_type == 1) {
		h->transport_id     = raw + 2;
		h->destination_hash = raw + 2 + ADDRLEN;
		h->context          = raw[2 + 2*ADDRLEN];
	} else {
		h->transport_id     = NULL;
		h->destination_hash = raw + 2;
		h->context          = raw[2 + ADDRLEN];
	}
	h->payload     = raw + header_len;
	h->payload_len = len - header_len;

	return OK;
}

static enum reason parse_announce(const struct header *h, struct announce *a,
                                  size_t *got, size_t *need)
{
	size_t minimum, at;

	minimum = KEYSIZE + NAMEHASHLEN + RANDHASHLEN + SIGLEN;
	if (h->context_flag == 1)
		minimum += RATCHETLEN;

	if (h->payload_len < minimum) {
		*got = h->payload_len; *need = minimum;
		return SHORT_PAYLOAD;
	}

	at = 0;
	a->public_key  = h->payload + at; at += KEYSIZE;
	a->name_hash   = h->payload + at; at += NAMEHASHLEN;
	a->random_hash = h->payload + at; at += RANDHASHLEN;
	if (h->context_flag == 1) {
		a->ratchet = h->payload + at; at += RATCHETLEN;
	} else {
		a->ratchet = NULL;
	}
	a->signature    = h->payload + at; at += SIGLEN;
	a->app_data     = h->payload + at;
	a->app_data_len = h->payload_len - at;

	return OK;
}

/* app_data is transmitted after the signature but signed before it.
 * Getting this wrong is the most likely reason for a valid announce to
 * be rejected, so the assembled bytes are printed. */
static size_t assemble_signed(const struct header *h, const struct announce *a,
                              uint8_t *out)
{
	size_t n = 0;

	memcpy(out + n, h->destination_hash, ADDRLEN);   n += ADDRLEN;
	memcpy(out + n, a->public_key,       KEYSIZE);   n += KEYSIZE;
	memcpy(out + n, a->name_hash,    NAMEHASHLEN);   n += NAMEHASHLEN;
	memcpy(out + n, a->random_hash,  RANDHASHLEN);   n += RANDHASHLEN;
	if (a->ratchet != NULL) {
		memcpy(out + n, a->ratchet, RATCHETLEN); n += RATCHETLEN;
	}
	memcpy(out + n, a->app_data, a->app_data_len);   n += a->app_data_len;

	return n;
}

static void print_invalid(enum reason r, size_t got, size_t need)
{
	switch (r) {
	case SHORT_HEADER:
		field("invalid", "short-header");
		field("length", "%zu", got);
		field("minimum_length", "%zu", need);
		break;
	case HOP_LIMIT:
		field("invalid", "hop-limit");
		field("hops", "%zu", got);
		field("hop_limit", "%zu", need);
		break;
	case SHORT_PAYLOAD:
		field("invalid", "short-payload");
		field("payload_length", "%zu", got);
		field("minimum_length", "%zu", need);
		break;
	case OK:
		break;
	}
}

static const struct {
	unsigned    byte;
	const char *name;
} contexts[] = {
	{ 0x00, "none" },
	{ 0x0b, "path_response" },
	{ 0xfa, "keepalive" },
	{ 0xfb, "link_identify" },
	{ 0xfc, "link_close" },
	{ 0xfd, "link_proof" },
	{ 0xfe, "link_rtt" },
	{ 0xff, "link_request_proof" },
};

static const char *context_name(unsigned c)
{
	size_t i;

	for (i = 0; i < sizeof contexts / sizeof contexts[0]; i++)
		if (contexts[i].byte == c)
			return contexts[i].name;
	return NULL;
}

static void print_header(const struct header *h)
{
	field("flags", "%02x", h->flags);
	field("header_type", "%u", h->header_type + 1);
	field("context_flag", "%s", h->context_flag ? "set" : "unset");
	field("transport_type", "%s", xport_types[h->transport_type]);
	field("destination_type", "%s", dest_types[h->destination_type]);
	field("packet_type", "%s", packet_types[h->packet_type]);
	field("hops", "%u", h->hops);
	if (h->transport_id != NULL)
		field_hex("transport_id", h->transport_id, ADDRLEN);
	else
		field("transport_id", "-");
	field_hex("destination_hash", h->destination_hash, ADDRLEN);
	if (context_name(h->context) != NULL)
		field("context", "%s", context_name(h->context));
	else
		field("context", "%02x", h->context);
	field("payload_length", "%zu", h->payload_len);
}

static void print_announce(const struct header *h, const struct announce *a)
{
	uint8_t identity_hash[ADDRLEN], expected_hash[ADDRLEN];
	uint8_t material[NAMEHASHLEN + ADDRLEN];
	uint8_t signed_data[MAXBLOB];
	size_t  sdlen;

	truncated_hash(a->public_key, KEYSIZE, identity_hash, ADDRLEN);
	memcpy(material, a->name_hash, NAMEHASHLEN);
	memcpy(material + NAMEHASHLEN, identity_hash, ADDRLEN);
	truncated_hash(material, sizeof material, expected_hash, ADDRLEN);

	sdlen = assemble_signed(h, a, signed_data);

	print_header(h);
	field_hex("public_key", a->public_key, KEYSIZE);
	field_hex("name_hash", a->name_hash, NAMEHASHLEN);
	field_hex("random_hash", a->random_hash, RANDHASHLEN);
	if (a->ratchet != NULL)
		field_hex("ratchet", a->ratchet, RATCHETLEN);
	else
		field("ratchet", "-");
	field_hex("signature", a->signature, SIGLEN);
	if (a->app_data_len > 0)
		field_hex("app_data", a->app_data, a->app_data_len);
	else
		field("app_data", "-");
	field_hex("identity_hash", identity_hash, ADDRLEN);
	field_hex("expected_hash", expected_hash, ADDRLEN);
	field("destination_match", "%s",
	      memcmp(h->destination_hash, expected_hash, ADDRLEN) == 0 ? "yes" : "no");
	field_hex("signed_data", signed_data, sdlen);
	field("signature_valid", "%s",
	      ed25519_verify(a->public_key + KEYHALF, a->signature,
	                     signed_data, sdlen) ? "yes" : "no");
}

/* A token is iv || ciphertext || hmac. Opening one is the same sequence
 * for a packet addressed to a destination and for one on a link; only
 * the key differs, and where that key comes from is the whole of what
 * the two kinds do not share. RNS/Cryptography/Token.py:100. */
struct token {
	const uint8_t *iv, *ciphertext, *mac;
	size_t   ctlen, ptlen;
	uint8_t  plain[MAXBLOB];
	int      mac_ok, opened, keyed;
};

/* A null derived key means no key agreement was possible. The token is
 * still laid out, because its three parts are in the packet, but no
 * verdict about it can be reached. */
static void token_open(const uint8_t *p, size_t len,
                       const uint8_t *derived, struct token *t)
{
	uint8_t expected[MACLEN], signed_part[MAXBLOB];

	t->iv         = p;
	t->ciphertext = p + IVLEN;
	t->ctlen      = len - TOKEN_OVERHEAD;
	t->mac        = p + len - MACLEN;
	t->ptlen      = 0;
	t->opened     = 0;
	t->mac_ok     = 0;
	t->keyed      = derived != NULL;

	if (!t->keyed)
		return;

	memcpy(signed_part, t->iv, IVLEN);
	memcpy(signed_part + IVLEN, t->ciphertext, t->ctlen);
	hmac_sha256(derived, MACLEN, signed_part, IVLEN + t->ctlen, expected);
	t->mac_ok = memcmp(t->mac, expected, MACLEN) == 0;

	if (t->mac_ok && t->ctlen > 0 && t->ctlen % 16 == 0 &&
	    aes256_cbc_decrypt(derived + MACLEN, t->iv, t->ciphertext, t->ctlen,
	                       t->plain) == 0 &&
	    pkcs7_unpad(t->plain, t->ctlen, &t->ptlen) == 0)
		t->opened = 1;
}

static void print_token(const struct token *t)
{
	field_hex("iv", t->iv, IVLEN);
	field_hex("ciphertext", t->ciphertext, t->ctlen);
	field_hex("hmac", t->mac, MACLEN);
}

static void print_keys(const uint8_t *shared, const uint8_t *derived)
{
	if (shared == NULL) {
		field("shared_key", "-");
		field("signing_key", "-");
		field("encryption_key", "-");
		return;
	}
	field_hex("shared_key", shared, KEYHALF);
	field_hex("signing_key", derived, MACLEN);
	field_hex("encryption_key", derived + MACLEN, MACLEN);
}

static void print_plaintext(const struct token *t)
{
	if (!t->keyed) {
		field("hmac_valid", "-");
		field("plaintext_length", "-");
		field("plaintext", "-");
		return;
	}
	field("hmac_valid", "%s", t->mac_ok ? "yes" : "no");
	if (!t->opened) {
		field("plaintext_length", "-");
		field("plaintext", "-");
		return;
	}
	field("plaintext_length", "%zu", t->ptlen);
	if (t->ptlen > 0)
		field_hex("plaintext", t->plain, t->ptlen);
	else
		field("plaintext", "-");
}

static void dump_encrypted(struct blob *b, int nblobs)
{
	struct header h;
	struct token t;
	enum reason r;
	size_t got = 0, need = 0;
	const uint8_t *ephemeral;
	uint8_t pub[KEYSIZE], identity_hash[ADDRLEN];
	uint8_t agree[KEYHALF], shared[KEYHALF], derived[DERIVEDLEN];
	uint8_t ratchet_pub[KEYHALF];
	int agreed;

	if (nblobs != 3)
		fatal("encrypted: expected 3 blobs, got %d", nblobs);
	if (b[0].len != KEYSIZE)
		fatal("encrypted: private key is %zu bytes, expected %d", b[0].len, KEYSIZE);
	if (!b[1].absent && b[1].len != KEYHALF)
		fatal("encrypted: ratchet key is %zu bytes, expected %d", b[1].len, KEYHALF);

	field_blob("recipient_private", &b[0]);
	field_blob("ratchet_private", &b[1]);

	if ((r = parse_header(b[2].data, b[2].len, &h, &got, &need)) != OK) {
		print_invalid(r, got, need);
		return;
	}

	if (h.payload_len < KEYHALF + TOKEN_OVERHEAD) {
		print_invalid(SHORT_PAYLOAD, h.payload_len, KEYHALF + TOKEN_OVERHEAD);
		return;
	}

	ephemeral = h.payload;

	/* The salt is the recipient's identity hash, derived from its own
	 * public key, even when the shared secret came from a ratchet.
	 * RNS/Identity.py:841. */
	crypto_scalarmult_base(pub, b[0].data);
	ed25519_public(b[0].data + KEYHALF, pub + KEYHALF);
	truncated_hash(pub, KEYSIZE, identity_hash, ADDRLEN);

	if (b[1].absent) {
		memcpy(agree, b[0].data, KEYHALF);
	} else {
		memcpy(agree, b[1].data, KEYHALF);
		crypto_scalarmult_base(ratchet_pub, b[1].data);
	}

	agreed = x25519_shared(shared, agree, ephemeral);
	if (agreed)
		hkdf_sha256(shared, KEYHALF, identity_hash, ADDRLEN, NULL, 0,
		            derived, DERIVEDLEN);
	token_open(h.payload + KEYHALF, h.payload_len - KEYHALF,
	           agreed ? derived : NULL, &t);

	print_header(&h);
	field_hex("ephemeral_public", ephemeral, KEYHALF);
	print_token(&t);
	field_hex("identity_hash", identity_hash, ADDRLEN);
	if (b[1].absent)
		field("ratchet_public", "-");
	else
		field_hex("ratchet_public", ratchet_pub, KEYHALF);
	print_keys(agreed ? shared : NULL, derived);
	print_plaintext(&t);
}

static void dump_announce(struct blob *b, int nblobs)
{
	struct header h;
	struct announce a;
	enum reason r;
	size_t got = 0, need = 0;

	if (nblobs != 1)
		fatal("announce: expected 1 blob, got %d", nblobs);

	if ((r = parse_header(b[0].data, b[0].len, &h, &got, &need)) != OK ||
	    (r = parse_announce(&h, &a, &got, &need)) != OK) {
		print_invalid(r, got, need);
		return;
	}

	print_announce(&h, &a);
}

/* A packet to a plain destination. Destination.encrypt returns the
 * plaintext unchanged for this type, so the payload is the data, with
 * no ephemeral key, no token and no padding. RNS/Destination.py:603.
 *
 * There is nothing to decrypt and therefore nothing here that could be
 * got wrong quietly: a decoder that treats every packet as encrypted
 * finds 80 bytes of overhead that are not there. */
static void dump_plain(struct blob *b, int nblobs)
{
	struct header h;
	enum reason r;
	size_t got = 0, need = 0;

	if (nblobs != 1)
		fatal("plain: expected 1 blob, got %d", nblobs);

	if ((r = parse_header(b[0].data, b[0].len, &h, &got, &need)) != OK) {
		print_invalid(r, got, need);
		return;
	}

	print_header(&h);
	field("plaintext_length", "%zu", h.payload_len);
	field_hex("plaintext", h.payload, h.payload_len);
}

/* The bytes a packet is hashed over. The low four flag bits and the hop
 * count are excluded, so that the hash survives a hop.
 * RNS/Packet.py:348. */
static size_t hashable_part(const uint8_t *raw, size_t len,
                            const struct header *h, uint8_t *out)
{
	size_t from = h->header_type ? 2 + ADDRLEN : 2;

	out[0] = raw[0] & 0x0f;
	memcpy(out + 1, raw + from, len - from);
	return 1 + len - from;
}

/* The link id is that hash truncated, with any signalling bytes chopped
 * off the end first, so that signalling the MTU does not change the
 * identity of the link. RNS/Link.py:336. */
static void link_id_of(const uint8_t *raw, size_t len,
                       const struct header *h, uint8_t *out)
{
	uint8_t part[MAXBLOB];
	size_t n = hashable_part(raw, len, h, part);

	if (h->payload_len > ECPUBSIZE)
		n -= h->payload_len - ECPUBSIZE;

	truncated_hash(part, n, out, ADDRLEN);
}

/* The hash a proof is taken over: the same bytes, untrimmed and not
 * truncated. RNS/Packet.py:344. */
static void packet_hash_of(const uint8_t *raw, size_t len,
                           const struct header *h, uint8_t out[32])
{
	uint8_t part[MAXBLOB];

	sha256(part, hashable_part(raw, len, h, part), out);
}

static void print_mode(unsigned mode)
{
	if (mode == 0x01)
		field("mode", "aes256_cbc");
	else
		field("mode", "%02x", mode);
}

static void dump_linkrequest(struct blob *b, int nblobs)
{
	struct header h;
	enum reason r;
	size_t got = 0, need = 0;
	uint8_t link_id[ADDRLEN];
	unsigned mode, mtu = 0, value;
	int signalled;

	if (nblobs != 1)
		fatal("linkrequest: expected 1 blob, got %d", nblobs);

	if ((r = parse_header(b[0].data, b[0].len, &h, &got, &need)) != OK) {
		print_invalid(r, got, need);
		return;
	}

	signalled = h.payload_len == ECPUBSIZE + SIGNALLEN;
	if (!signalled && h.payload_len != ECPUBSIZE) {
		field("invalid", "invalid-length");
		field("payload_length", "%zu", h.payload_len);
		field("accepted_length", "%d", ECPUBSIZE);
		field("signalled_length", "%d", ECPUBSIZE + SIGNALLEN);
		return;
	}

	if (signalled) {
		value = ((unsigned)h.payload[ECPUBSIZE] << 16) |
		        ((unsigned)h.payload[ECPUBSIZE + 1] << 8) |
		        h.payload[ECPUBSIZE + 2];
		mode = (value >> 21) & 0x07;
		mtu  = value & MTU_BYTEMASK;
	} else {
		mode = MODE_DEFAULT;
	}

	link_id_of(b[0].data, b[0].len, &h, link_id);

	print_header(&h);
	field_hex("x25519_public", h.payload, KEYHALF);
	field_hex("ed25519_public", h.payload + KEYHALF, KEYHALF);
	if (signalled)
		field_hex("signalling", h.payload + ECPUBSIZE, SIGNALLEN);
	else
		field("signalling", "-");
	print_mode(mode);
	if (signalled)
		field("mtu", "%u", mtu);
	else
		field("mtu", "-");
	field_hex("link_id", link_id, ADDRLEN);
}

static void dump_linkproof(struct blob *b, int nblobs)
{
	struct header h, rh;
	enum reason r;
	size_t got = 0, need = 0, sdlen = 0;
	const uint8_t *signature, *x25519, *signalling, *signer;
	uint8_t link_id[ADDRLEN], signed_data[MAXBLOB];
	unsigned mode, mtu = 0, value;
	int signalled;

	if (nblobs != 3)
		fatal("linkproof: expected 3 blobs, got %d", nblobs);
	if (b[1].len != KEYSIZE)
		fatal("linkproof: identity key is %zu bytes, expected %d", b[1].len, KEYSIZE);

	field_blob("link_request", &b[0]);
	field_blob("signer_public", &b[1]);

	if ((r = parse_header(b[0].data, b[0].len, &rh, &got, &need)) != OK)
		fatal("linkproof: the link request does not decode");

	if ((r = parse_header(b[2].data, b[2].len, &h, &got, &need)) != OK) {
		print_invalid(r, got, need);
		return;
	}

	signalled = h.payload_len == SIGLEN + KEYHALF + SIGNALLEN;
	if (!signalled && h.payload_len != SIGLEN + KEYHALF) {
		field("invalid", "invalid-length");
		field("payload_length", "%zu", h.payload_len);
		field("accepted_length", "%d", SIGLEN + KEYHALF);
		field("signalled_length", "%d", SIGLEN + KEYHALF + SIGNALLEN);
		return;
	}

	signature  = h.payload;
	x25519     = h.payload + SIGLEN;
	signalling = h.payload + SIGLEN + KEYHALF;
	signer     = b[1].data + KEYHALF;

	if (signalled) {
		value = ((unsigned)signalling[0] << 16) |
		        ((unsigned)signalling[1] << 8) | signalling[2];
		mode = (value >> 21) & 0x07;
		mtu  = value & MTU_BYTEMASK;
	} else {
		mode = MODE_DEFAULT;
	}

	link_id_of(b[0].data, b[0].len, &rh, link_id);

	memcpy(signed_data + sdlen, link_id, ADDRLEN);  sdlen += ADDRLEN;
	memcpy(signed_data + sdlen, x25519, KEYHALF);   sdlen += KEYHALF;
	memcpy(signed_data + sdlen, signer, KEYHALF);   sdlen += KEYHALF;
	if (signalled) {
		memcpy(signed_data + sdlen, signalling, SIGNALLEN);
		sdlen += SIGNALLEN;
	}

	print_header(&h);
	field_hex("link_id", link_id, ADDRLEN);
	field("link_id_match", "%s",
	      memcmp(h.destination_hash, link_id, ADDRLEN) == 0 ? "yes" : "no");
	field_hex("signature", signature, SIGLEN);
	field_hex("x25519_public", x25519, KEYHALF);
	if (signalled)
		field_hex("signalling", signalling, SIGNALLEN);
	else
		field("signalling", "-");
	print_mode(mode);
	if (signalled)
		field("mtu", "%u", mtu);
	else
		field("mtu", "-");
	field_hex("signer_ed25519", signer, KEYHALF);
	field_hex("signed_data", signed_data, sdlen);
	field("signature_valid", "%s",
	      ed25519_verify(signer, signature, signed_data, sdlen) ? "yes" : "no");
}

static void dump_linkdata(struct blob *b, int nblobs)
{
	struct header h, rh;
	struct token t;
	enum reason r;
	size_t got = 0, need = 0;
	const uint8_t *initiator_public;
	uint8_t link_id[ADDRLEN], shared[KEYHALF], derived[DERIVEDLEN];
	uint8_t identity_hash[ADDRLEN], signed_data[ADDRLEN + KEYSIZE];
	int agreed;

	if (nblobs != 3)
		fatal("linkdata: expected 3 blobs, got %d", nblobs);
	if (b[1].len != KEYHALF)
		fatal("linkdata: private key is %zu bytes, expected %d", b[1].len, KEYHALF);

	field_blob("link_request", &b[0]);
	field_blob("responder_private", &b[1]);

	if (parse_header(b[0].data, b[0].len, &rh, &got, &need) != OK)
		fatal("linkdata: the link request does not decode");

	if ((r = parse_header(b[2].data, b[2].len, &h, &got, &need)) != OK) {
		print_invalid(r, got, need);
		return;
	}

	link_id_of(b[0].data, b[0].len, &rh, link_id);

	print_header(&h);
	field_hex("link_id", link_id, ADDRLEN);
	field("link_id_match", "%s",
	      memcmp(h.destination_hash, link_id, ADDRLEN) == 0 ? "yes" : "no");

	/* Keepalives carry no data and are the one link packet the
	 * reference does not encrypt. RNS/Packet.py:206. */
	if (h.context == 0xfa) {
		field("encrypted", "no");
		field("plaintext_length", "%zu", h.payload_len);
		if (h.payload_len > 0)
			field_hex("plaintext", h.payload, h.payload_len);
		else
			field("plaintext", "-");
		return;
	}

	field("encrypted", "yes");

	if (h.payload_len < TOKEN_OVERHEAD) {
		print_invalid(SHORT_PAYLOAD, h.payload_len, TOKEN_OVERHEAD);
		return;
	}

	/* Both ends already hold the shared secret, so no packet on the
	 * link carries an ephemeral key. The salt is the link id, which is
	 * in no packet either. RNS/Link.py:351, RNS/Link.py:607. */
	initiator_public = rh.payload;
	agreed = x25519_shared(shared, b[1].data, initiator_public);
	if (agreed)
		hkdf_sha256(shared, KEYHALF, link_id, ADDRLEN, NULL, 0,
		            derived, DERIVEDLEN);
	token_open(h.payload, h.payload_len, agreed ? derived : NULL, &t);

	print_token(&t);
	print_keys(agreed ? shared : NULL, derived);
	print_plaintext(&t);
	if (!t.opened)
		return;

	/* An identify proof names the initiator, which nothing else on a
	 * link does. Its signature covers the link id, so it cannot be
	 * replayed onto another link. RNS/Link.py:464. */
	if (h.context == 0xfb && t.ptlen == KEYSIZE + SIGLEN) {
		truncated_hash(t.plain, KEYSIZE, identity_hash, ADDRLEN);
		memcpy(signed_data, link_id, ADDRLEN);
		memcpy(signed_data + ADDRLEN, t.plain, KEYSIZE);

		field_hex("identity_public", t.plain, KEYSIZE);
		field_hex("identity_hash", identity_hash, ADDRLEN);
		field_hex("identity_signed", signed_data, ADDRLEN + KEYSIZE);
		field("identity_valid", "%s",
		      ed25519_verify(t.plain + KEYHALF, t.plain + KEYSIZE,
		                     signed_data, ADDRLEN + KEYSIZE) ? "yes" : "no");
	}
}

/* A proof is what a receiver sends back for a data packet it accepted.
 * It is addressed to the first 16 bytes of the proved packet's hash
 * rather than to a destination, which is how the sender recognises the
 * answer to its own packet. RNS/Packet.py:378. */
static void dump_proof(struct blob *b, int nblobs)
{
	struct header h, ph;
	enum reason r;
	size_t got = 0, need = 0;
	const uint8_t *signature, *signer;
	uint8_t packet_hash[32];
	int explicit_form;

	if (nblobs != 3)
		fatal("proof: expected 3 blobs, got %d", nblobs);
	if (b[1].len != KEYSIZE)
		fatal("proof: signer key is %zu bytes, expected %d", b[1].len, KEYSIZE);

	field_blob("proved_packet", &b[0]);
	field_blob("signer_public", &b[1]);

	if (parse_header(b[0].data, b[0].len, &ph, &got, &need) != OK)
		fatal("proof: the proved packet does not decode");

	if ((r = parse_header(b[2].data, b[2].len, &h, &got, &need)) != OK) {
		print_invalid(r, got, need);
		return;
	}

	explicit_form = h.payload_len == 32 + SIGLEN;
	if (!explicit_form && h.payload_len != SIGLEN) {
		field("invalid", "invalid-length");
		field("payload_length", "%zu", h.payload_len);
		field("implicit_length", "%d", SIGLEN);
		field("explicit_length", "%d", 32 + SIGLEN);
		return;
	}

	packet_hash_of(b[0].data, b[0].len, &ph, packet_hash);
	signature = explicit_form ? h.payload + 32 : h.payload;
	signer    = b[1].data + KEYHALF;

	print_header(&h);
	field("form", "%s", explicit_form ? "explicit" : "implicit");
	field_hex("packet_hash", packet_hash, sizeof packet_hash);
	if (explicit_form)
		field_hex("proof_hash", h.payload, 32);
	else
		field("proof_hash", "-");
	field("hash_match", "%s",
	      !explicit_form || memcmp(h.payload, packet_hash, 32) == 0 ? "yes" : "no");
	field_hex("proof_destination", packet_hash, ADDRLEN);
	field("destination_match", "%s",
	      memcmp(h.destination_hash, packet_hash, ADDRLEN) == 0 ? "yes" : "no");
	field_hex("signature", signature, SIGLEN);
	field_hex("signer_ed25519", signer, KEYHALF);
	field("signature_valid", "%s",
	      ed25519_verify(signer, signature, packet_hash, sizeof packet_hash) ? "yes" : "no");
}

/* The mask covers the whole frame except the access code itself, which
 * has to be readable before the mask it keys can be generated. Both
 * header bytes are masked; the IFAC flag is put back afterwards.
 * RNS/Transport.py:1094, RNS/Transport.py:1456. */
static void ifac_mask(const uint8_t *ifac, size_t ifac_size,
                      const uint8_t key[KEYSIZE],
                      const uint8_t *in, size_t len, uint8_t *out)
{
	static uint8_t mask[MAXBLOB];
	size_t i;

	hkdf_sha256(ifac, ifac_size, key, KEYSIZE, NULL, 0, mask, len);

	for (i = 0; i < len; i++) {
		if (i <= 1 || i > ifac_size + 1)
			out[i] = in[i] ^ mask[i];
		else
			out[i] = in[i];
	}
}

/* Packet.unpack never reads bit 7 (RNS/Packet.py:243). Transport does,
 * and a frame on an interface with a named network or a passphrase is
 * not a packet until it has been unmasked. See doc/packet. */
static void dump_ifac(struct blob *b, int nblobs)
{
	static uint8_t unmasked[MAXBLOB], packet[MAXBLOB];
	const uint8_t *ifac;
	uint8_t expected[SIGLEN];
	size_t ifac_size, plen;

	if (nblobs != 3)
		fatal("ifac: expected 3 blobs, got %d", nblobs);
	if (b[0].len != KEYSIZE)
		fatal("ifac: interface key is %zu bytes, expected %d", b[0].len, KEYSIZE);
	if (b[1].len != 1)
		fatal("ifac: access code size is %zu bytes, expected 1", b[1].len);

	ifac_size = b[1].data[0];
	if (ifac_size > SIGLEN)
		fatal("ifac: access code of %zu bytes exceeds the signature", ifac_size);
	if (b[2].len <= 2 + ifac_size)
		fatal("ifac: frame of %zu bytes holds no packet", b[2].len);

	ifac = b[2].data + 2;
	ifac_mask(ifac, ifac_size, b[0].data, b[2].data, b[2].len, unmasked);

	/* The access code is not part of the packet, and the flag that
	 * announced it is cleared before the signature is checked. */
	plen = b[2].len - ifac_size;
	packet[0] = unmasked[0] & 0x7f;
	packet[1] = unmasked[1];
	memcpy(packet + 2, unmasked + 2 + ifac_size, plen - 2);

	ed25519_sign(b[0].data + KEYHALF, packet, plen, expected);

	field_hex("ifac_key", b[0].data, KEYSIZE);
	field("ifac_size", "%zu", ifac_size);
	field("frame_length", "%zu", b[2].len);
	field_hex("ifac", ifac, ifac_size);
	field_hex("packet", packet, plen);
	field_hex("expected_ifac", expected + SIGLEN - ifac_size, ifac_size);
	field("ifac_valid", "%s",
	      memcmp(ifac, expected + SIGLEN - ifac_size, ifac_size) == 0 ? "yes" : "no");
}

/* Rebuilding raw from expect. The layout below is the one the decoders
 * above read, written out a second time and in the other direction: a
 * vector of the encode class is one whose expect holds every byte of
 * raw, and cmd/check tests that claim by diffing the result. A field
 * whose value is "-" contributes no bytes, which is how the format
 * spells every optional field. */

struct out {
	char   hex[MAXBLOB*2 + 2];
	size_t len;
};

static void put(struct out *o, const char *hex)
{
	size_t n = strlen(hex), i;

	if (n % 2 != 0)
		fatal("odd hex length in %s", hex);
	for (i = 0; i < n; i++)
		if (unhex(hex[i]) < 0)
			fatal("bad hex in %s", hex);
	if (o->len + n >= sizeof o->hex)
		fatal("rebuilt blob exceeds %d bytes", MAXBLOB);

	memcpy(o->hex + o->len, hex, n);
	o->len += n;
	o->hex[o->len] = '\0';
}

static void put_byte(struct out *o, unsigned v)
{
	char b[3];

	snprintf(b, sizeof b, "%02x", v & 0xff);
	put(o, b);
}

static void put_bytes(struct out *o, const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		put_byte(o, p[i]);
}

/* Absent fields carry no bytes, so an optional one needs no separate
 * case anywhere in the encoders. */
static void put_field(struct out *o, struct kv *f, int n, const char *name)
{
	const char *v = lookup(f, n, name);

	if (strcmp(v, "-") != 0)
		put(o, v);
}

static void put_hops(struct out *o, struct kv *f, int n)
{
	const char *v = lookup(f, n, "hops");
	char *end;
	unsigned long hops = strtoul(v, &end, 10);

	if (*end != '\0' || hops >= MAX_HOPS)
		fatal("unusable hops value %s", v);
	put_byte(o, (unsigned)hops);
}

static void put_context(struct out *o, struct kv *f, int n)
{
	const char *v = lookup(f, n, "context");
	size_t i;

	for (i = 0; i < sizeof contexts / sizeof contexts[0]; i++)
		if (strcmp(contexts[i].name, v) == 0) {
			put_byte(o, contexts[i].byte);
			return;
		}
	if (strlen(v) != 2)
		fatal("unusable context value %s", v);
	put(o, v);
}

static void put_header(struct out *o, struct kv *f, int n)
{
	put_field(o, f, n, "flags");
	put_hops(o, f, n);
	put_field(o, f, n, "transport_id");
	put_field(o, f, n, "destination_hash");
	put_context(o, f, n);
}

static void emit(struct out *o)
{
	printf("%s\n", o->hex);
	o->len = 0;
	o->hex[0] = '\0';
}

/* A blob that is one whole field is written out as it stands, "-"
 * included: an absent blob is a line, not a missing line. */
static void emit_field(struct kv *f, int n, const char *name)
{
	printf("%s\n", lookup(f, n, name));
}

static void encode_identity(struct kv *f, int n)
{
	emit_field(f, n, "public_key");
}

static void encode_keyset(struct kv *f, int n)
{
	emit_field(f, n, "private_key");
}

static void encode_destination(struct kv *f, int n)
{
	emit_field(f, n, "name");
	emit_field(f, n, "identity_hash");
}

static void encode_announce(struct kv *f, int n)
{
	struct out o = { "", 0 };

	put_header(&o, f, n);
	put_field(&o, f, n, "public_key");
	put_field(&o, f, n, "name_hash");
	put_field(&o, f, n, "random_hash");
	put_field(&o, f, n, "ratchet");
	put_field(&o, f, n, "signature");
	put_field(&o, f, n, "app_data");
	emit(&o);
}

static void encode_encrypted(struct kv *f, int n)
{
	struct out o = { "", 0 };

	emit_field(f, n, "recipient_private");
	emit_field(f, n, "ratchet_private");

	put_header(&o, f, n);
	put_field(&o, f, n, "ephemeral_public");
	put_field(&o, f, n, "iv");
	put_field(&o, f, n, "ciphertext");
	put_field(&o, f, n, "hmac");
	emit(&o);
}

static void encode_plain(struct kv *f, int n)
{
	struct out o = { "", 0 };

	put_header(&o, f, n);
	put_field(&o, f, n, "plaintext");
	emit(&o);
}

static void encode_linkrequest(struct kv *f, int n)
{
	struct out o = { "", 0 };

	put_header(&o, f, n);
	put_field(&o, f, n, "x25519_public");
	put_field(&o, f, n, "ed25519_public");
	put_field(&o, f, n, "signalling");
	emit(&o);
}

static void encode_proof(struct kv *f, int n)
{
	struct out o = { "", 0 };

	emit_field(f, n, "proved_packet");
	emit_field(f, n, "signer_public");

	put_header(&o, f, n);
	put_field(&o, f, n, "proof_hash");
	put_field(&o, f, n, "signature");
	emit(&o);
}

static void encode_linkproof(struct kv *f, int n)
{
	struct out o = { "", 0 };

	emit_field(f, n, "link_request");
	emit_field(f, n, "signer_public");

	put_header(&o, f, n);
	put_field(&o, f, n, "signature");
	put_field(&o, f, n, "x25519_public");
	put_field(&o, f, n, "signalling");
	emit(&o);
}

/* The one encoder that is not a concatenation. Going out, the flag is
 * set, the access code is inserted after the two header bytes, and the
 * same mask is applied. RNS/Transport.py:1081. */
static void encode_ifac(struct kv *f, int n)
{
	static uint8_t packet[MAXBLOB], frame[MAXBLOB], masked[MAXBLOB];
	struct blob key, code, pkt;
	struct out o = { "", 0 };
	size_t len;

	decode_hex(&key, lookup(f, n, "ifac_key"), strlen(lookup(f, n, "ifac_key")), "ifac_key");
	decode_hex(&code, lookup(f, n, "ifac"), strlen(lookup(f, n, "ifac")), "ifac");
	decode_hex(&pkt, lookup(f, n, "packet"), strlen(lookup(f, n, "packet")), "packet");

	if (key.len != KEYSIZE)
		fatal("ifac: interface key is %zu bytes, expected %d", key.len, KEYSIZE);
	if (pkt.len < 2)
		fatal("ifac: packet of %zu bytes has no header", pkt.len);

	memcpy(packet, pkt.data, pkt.len);
	len = pkt.len + code.len;

	frame[0] = packet[0] | 0x80;
	frame[1] = packet[1];
	memcpy(frame + 2, code.data, code.len);
	memcpy(frame + 2 + code.len, packet + 2, pkt.len - 2);

	ifac_mask(code.data, code.len, key.data, frame, len, masked);
	masked[0] |= 0x80;

	emit_field(f, n, "ifac_key");
	put_byte(&o, (unsigned)code.len);
	emit(&o);

	put_bytes(&o, masked, len);
	emit(&o);
}

/* A keepalive is the one link packet the reference does not encrypt, so
 * its payload is the plaintext and there is no token to write out. */
static void encode_linkdata(struct kv *f, int n)
{
	struct out o = { "", 0 };

	emit_field(f, n, "link_request");
	emit_field(f, n, "responder_private");

	put_header(&o, f, n);
	if (strcmp(lookup(f, n, "encrypted"), "no") == 0) {
		put_field(&o, f, n, "plaintext");
	} else {
		put_field(&o, f, n, "iv");
		put_field(&o, f, n, "ciphertext");
		put_field(&o, f, n, "hmac");
	}
	emit(&o);
}

/* Every kind, and for each the two directions. A kind with no
 * encoder is one no vector can claim the encode class for: its raw
 * holds something expect does not record. */
static const struct {
	const char *name;
	void (*decode)(struct blob *, int);
	void (*encode)(struct kv *, int);
} kinds[] = {
	{ "identity",    dump_identity,    encode_identity    },
	{ "keyset",      dump_keyset,      encode_keyset      },
	{ "destination", dump_destination, encode_destination },
	{ "signature",   dump_signature,   NULL               },
	{ "sign",        dump_sign,        NULL               },
	{ "announce",    dump_announce,    encode_announce    },
	{ "plain",       dump_plain,       encode_plain       },
	{ "encrypted",   dump_encrypted,   encode_encrypted   },
	{ "linkrequest", dump_linkrequest, encode_linkrequest },
	{ "linkproof",   dump_linkproof,   encode_linkproof   },
	{ "linkdata",    dump_linkdata,    encode_linkdata    },
	{ "proof",       dump_proof,       encode_proof       },
	{ "ifac",        dump_ifac,        encode_ifac        },
};

int main(int argc, char **argv)
{
	static struct blob blobs[MAXBLOBS];
	static struct kv fields[MAXFIELDS];
	const char *kind, *path;
	size_t i;
	int n, encode = 0;

	argv0 = argv[0];
	if (argc == 4 && strcmp(argv[1], "-e") == 0) {
		encode = 1;
		kind = argv[2];
		path = argv[3];
	} else if (argc == 3) {
		kind = argv[1];
		path = argv[2];
	} else {
		fprintf(stderr, "usage: %s kind rawfile\n", argv0);
		fprintf(stderr, "       %s -e kind expectfile\n", argv0);
		return 2;
	}

	for (i = 0; i < sizeof kinds / sizeof kinds[0]; i++) {
		if (strcmp(kinds[i].name, kind) != 0)
			continue;
		if (!encode) {
			n = readraw(path, blobs, MAXBLOBS);
			kinds[i].decode(blobs, n);
		} else if (kinds[i].encode == NULL) {
			fatal("kind %s is not of the encode class", kind);
		} else {
			n = readexpect(path, fields, MAXFIELDS);
			kinds[i].encode(fields, n);
		}
		return 0;
	}

	fatal("unknown kind %s", kind);
	return 1;
}
