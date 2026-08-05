/* dump - decode one Reticulum object and print its fields.
 *
 *	dump kind rawfile		decode raw, print fields
 *	dump -e kind expectfile		rebuild raw from fields
 *
 * The output of the first form is the expect file of a vector, so
 * checking is a diff. The second form exists for vectors of the encode
 * class, whose expect file claims to carry everything raw contains;
 * running it and diffing against raw is what turns that claim into a
 * test. See ../README.
 *
 * Every value dump prints is hex, a decimal number, or one of a fixed
 * set of keywords. Nothing else reaches a line. A destination name is
 * arbitrary bytes and is printed as hex for that reason: printed as
 * text, a newline in an aspect would forge or hide a field.
 *
 * dump is a second implementation of the wire format, independent of
 * python-rns. That is its purpose. It deliberately shares no code with
 * the generator. */

#include "aes256.h"
#include "hmac.h"
#include "sha256.h"
#include "tweetnacl.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXBLOB   8192
#define MAXBLOBS  8
#define MAXFIELDS 64
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
#define TOKEN_OVERHEAD (IVLEN + MACLEN)   /* RNS/Cryptography/Token.py:51 */
#define DERIVEDLEN   64
#define MAX_HOPS     128	/* RNS.Transport.PATHFINDER_M */
#define ECPUBSIZE    64		/* RNS/Link.py:70 */
#define SIGNALLEN    3		/* RNS/Link.py:80 */
#define MTU_BYTEMASK 0x1fffff	/* RNS/Link.py:144 */
#define MODE_DEFAULT 0x01	/* RNS/Link.py:134 */

static const char *argv0;

/* ---------------------------------------------------------------- output */

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

static void field_hex(const char *name, const uint8_t *p, size_t n)
{
	size_t i;

	printf("%-*s ", FIELDW, name);
	for (i = 0; i < n; i++)
		printf("%02x", p[i]);
	putchar('\n');
}

/* ----------------------------------------------------------------- input */

struct blob {
	uint8_t  data[MAXBLOB];
	size_t   len;
	int      absent;	/* the line was "-" */
};

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

/* raw: one hex blob per line, or "-" for an absent blob. */
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

/* expect: "name<padding>value" per line. Values never contain a space,
 * so the split is exact. */
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

/* --------------------------------------------------------------- crypto */

/* tweetnacl declares randombytes and leaves it to the caller. dump has
 * no use for randomness; the one place tweetnacl reaches for it is
 * crypto_sign_keypair, which is how an Ed25519 public key is derived
 * from a given seed without editing the vendored source. Serving that
 * call a chosen seed keeps tweetnacl unmodified. Any other call is a
 * bug and stops the program. See VENDOR. */

static unsigned char rb_seed[32];
static int rb_armed;

void randombytes(unsigned char *x, unsigned long long n)
{
	if (!rb_armed || n != 32)
		fatal("randombytes called outside seeded key derivation");
	memcpy(x, rb_seed, 32);
	rb_armed = 0;
}

static void ed25519_public(const uint8_t seed[32], uint8_t out[32])
{
	unsigned char sk[64];

	memcpy(rb_seed, seed, 32);
	rb_armed = 1;
	crypto_sign_keypair(out, sk);
}

static int ed25519_verify(const uint8_t pk[32], const uint8_t sig[64],
                          const uint8_t *msg, size_t mlen)
{
	static unsigned char sm[MAXBLOB + 64], m[MAXBLOB + 64];
	unsigned long long got;

	if (mlen > MAXBLOB)
		fatal("message of %zu bytes exceeds %d", mlen, MAXBLOB);

	memcpy(sm, sig, 64);
	memcpy(sm + 64, msg, mlen);

	return crypto_sign_open(m, &got, sm, (unsigned long long)mlen + 64, pk) == 0;
}

static void truncated_hash(const uint8_t *p, size_t n, uint8_t *out, size_t take)
{
	uint8_t full[32];

	sha256(p, n, full);
	memcpy(out, full, take);
}

/* ------------------------------------------------------------ decoding */

/* identity: one blob, the 64-byte public key. See ../doc/identity. */
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

/* keyset: one blob, the 64-byte private key. See ../doc/identity. */
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

/* destination: two blobs, the utf-8 name and the identity hash.
 * See ../doc/destination. */
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

/* signature: three blobs, public key, message, signature.
 * See ../doc/identity. */
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

/* announce: one blob, the whole packet. See ../doc/packet and
 * ../doc/announce. */

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

static const char *context_name(unsigned c)
{
	switch (c) {
	case 0x00: return "none";
	case 0x0b: return "path_response";
	case 0xfa: return "keepalive";
	case 0xfb: return "link_identify";
	case 0xfc: return "link_close";
	case 0xfd: return "link_proof";
	case 0xfe: return "link_rtt";
	case 0xff: return "link_request_proof";
	default:   return NULL;
	}
}

/* The header fields, shared by every packet kind. */
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

/* encrypted: three blobs, the recipient private key, the ratchet
 * private key or "-", and the packet. See ../doc/encryption. */
static void dump_encrypted(struct blob *b, int nblobs)
{
	struct header h;
	enum reason r;
	size_t got = 0, need = 0, ctlen, ptlen = 0;
	const uint8_t *ephemeral, *iv, *ciphertext, *mac;
	uint8_t pub[KEYSIZE], identity_hash[ADDRLEN];
	uint8_t agree[KEYHALF], shared[KEYHALF], derived[DERIVEDLEN];
	uint8_t expected[MACLEN], plain[MAXBLOB], ratchet_pub[KEYHALF];
	uint8_t signed_part[MAXBLOB];
	int mac_ok, decrypted = 0;

	if (nblobs != 3)
		fatal("encrypted: expected 3 blobs, got %d", nblobs);
	if (b[0].len != KEYSIZE)
		fatal("encrypted: private key is %zu bytes, expected %d", b[0].len, KEYSIZE);
	if (!b[1].absent && b[1].len != KEYHALF)
		fatal("encrypted: ratchet key is %zu bytes, expected %d", b[1].len, KEYHALF);

	if ((r = parse_header(b[2].data, b[2].len, &h, &got, &need)) != OK) {
		print_invalid(r, got, need);
		return;
	}

	if (h.payload_len < KEYHALF + TOKEN_OVERHEAD) {
		print_invalid(SHORT_PAYLOAD, h.payload_len, KEYHALF + TOKEN_OVERHEAD);
		return;
	}

	ephemeral  = h.payload;
	iv         = h.payload + KEYHALF;
	ciphertext = h.payload + KEYHALF + IVLEN;
	ctlen      = h.payload_len - KEYHALF - TOKEN_OVERHEAD;
	mac        = h.payload + h.payload_len - MACLEN;

	/* The salt is the recipient's identity hash, derived from its own
	 * public key, even when the shared secret came from a ratchet.
	 * RNS/Identity.py:836. */
	crypto_scalarmult_base(pub, b[0].data);
	ed25519_public(b[0].data + KEYHALF, pub + KEYHALF);
	truncated_hash(pub, KEYSIZE, identity_hash, ADDRLEN);

	if (b[1].absent) {
		memcpy(agree, b[0].data, KEYHALF);
	} else {
		memcpy(agree, b[1].data, KEYHALF);
		crypto_scalarmult_base(ratchet_pub, b[1].data);
	}

	crypto_scalarmult(shared, agree, ephemeral);
	hkdf_sha256(shared, KEYHALF, identity_hash, ADDRLEN, NULL, 0, derived, DERIVEDLEN);

	memcpy(signed_part, iv, IVLEN);
	memcpy(signed_part + IVLEN, ciphertext, ctlen);
	hmac_sha256(derived, MACLEN, signed_part, IVLEN + ctlen, expected);
	mac_ok = memcmp(mac, expected, MACLEN) == 0;

	if (mac_ok && ctlen > 0 && ctlen % 16 == 0 &&
	    aes256_cbc_decrypt(derived + MACLEN, iv, ciphertext, ctlen, plain) == 0 &&
	    pkcs7_unpad(plain, ctlen, &ptlen) == 0)
		decrypted = 1;

	print_header(&h);
	field_hex("ephemeral_public", ephemeral, KEYHALF);
	field_hex("iv", iv, IVLEN);
	field_hex("ciphertext", ciphertext, ctlen);
	field_hex("hmac", mac, MACLEN);
	field_hex("identity_hash", identity_hash, ADDRLEN);
	if (b[1].absent)
		field("ratchet_public", "-");
	else
		field_hex("ratchet_public", ratchet_pub, KEYHALF);
	field_hex("shared_key", shared, KEYHALF);
	field_hex("signing_key", derived, MACLEN);
	field_hex("encryption_key", derived + MACLEN, MACLEN);
	field("hmac_valid", "%s", mac_ok ? "yes" : "no");
	if (!decrypted) {
		field("plaintext_length", "-");
		field("plaintext", "-");
	} else {
		field("plaintext_length", "%zu", ptlen);
		if (ptlen > 0)
			field_hex("plaintext", plain, ptlen);
		else
			field("plaintext", "-");
	}
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

/* The link id is a truncated hash of the packet with the low four flag
 * bits and the hop count excluded, so that it survives a hop, and with
 * any signalling bytes chopped off the end, so that signalling the MTU
 * does not change the identity of the link. RNS/Link.py:336. */
static void link_id_of(const uint8_t *raw, size_t len,
                       const struct header *h, uint8_t *out)
{
	uint8_t part[MAXBLOB];
	size_t n, from;

	part[0] = raw[0] & 0x0f;
	from = h->header_type ? 2 + ADDRLEN : 2;
	memcpy(part + 1, raw + from, len - from);
	n = 1 + len - from;

	if (h->payload_len > ECPUBSIZE)
		n -= h->payload_len - ECPUBSIZE;

	truncated_hash(part, n, out, ADDRLEN);
}

static void print_mode(unsigned mode)
{
	if (mode == 0x01)
		field("mode", "aes256_cbc");
	else
		field("mode", "%02x", mode);
}

/* linkrequest: one blob, the whole packet. See ../doc/link. */
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

/* linkproof: three blobs, the link request, the public key of the
 * identity the request was addressed to, and the proof. See ../doc/link. */
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

/* ------------------------------------------------------------ encoding */

static void print_hex_field(const char *value)
{
	printf("%s\n", value);
}

static void encode_identity(struct kv *f, int n)
{
	print_hex_field(lookup(f, n, "public_key"));
}

static void encode_keyset(struct kv *f, int n)
{
	print_hex_field(lookup(f, n, "private_key"));
}

static void encode_destination(struct kv *f, int n)
{
	print_hex_field(lookup(f, n, "name"));
	print_hex_field(lookup(f, n, "identity_hash"));
}

/* ------------------------------------------------------------------ main */

int main(int argc, char **argv)
{
	struct blob blobs[MAXBLOBS];
	struct kv fields[MAXFIELDS];
	const char *kind, *path;
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

	if (encode) {
		n = readexpect(path, fields, MAXFIELDS);
		if (strcmp(kind, "identity") == 0)
			encode_identity(fields, n);
		else if (strcmp(kind, "keyset") == 0)
			encode_keyset(fields, n);
		else if (strcmp(kind, "destination") == 0)
			encode_destination(fields, n);
		else
			fatal("kind %s is not of the encode class", kind);
		return 0;
	}

	n = readraw(path, blobs, MAXBLOBS);

	if (strcmp(kind, "identity") == 0)
		dump_identity(blobs, n);
	else if (strcmp(kind, "keyset") == 0)
		dump_keyset(blobs, n);
	else if (strcmp(kind, "destination") == 0)
		dump_destination(blobs, n);
	else if (strcmp(kind, "signature") == 0)
		dump_signature(blobs, n);
	else if (strcmp(kind, "announce") == 0)
		dump_announce(blobs, n);
	else if (strcmp(kind, "encrypted") == 0)
		dump_encrypted(blobs, n);
	else if (strcmp(kind, "linkrequest") == 0)
		dump_linkrequest(blobs, n);
	else if (strcmp(kind, "linkproof") == 0)
		dump_linkproof(blobs, n);
	else
		fatal("unknown kind %s", kind);

	return 0;
}
