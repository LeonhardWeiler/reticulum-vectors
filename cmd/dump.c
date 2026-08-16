/* dump - decode one Reticulum object and print its fields.
 *
 *	dump kind rawfile		decode raw, print fields
 *	dump -e kind expectfile		rebuild raw from fields
 *	dump -l				list the kinds it knows
 *
 * Every value it prints is hex, a decimal number, or a keyword from a
 * fixed set.
*/

#include "aes.h"
#include "hmac.h"
#include "sha256.h"
#include "tweetnacl.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXBLOB   2048
#define MAXBLOBS  4
#define MAXFIELDS 40
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
#define TOKEN_OVERHEAD (IVLEN + MACLEN) /* RNS/Cryptography/Token.py#TOKEN_OVERHEAD */ 
#define DERIVEDLEN   64
#define MAX_HOPS     128	/* RNS.Transport.PATHFINDER_M */
#define ECPUBSIZE    64		/* RNS/Link.py#ECPUBSIZE */
#define SIGNALLEN    3		/* RNS/Link.py#LINK_MTU_SIZE */
#define MTU_BYTEMASK 0x1fffff	/* RNS/Link.py#MTU_BYTEMASK */
#define MODE_DEFAULT 0x01	/* RNS/Link.py#MODE_DEFAULT */
#define ENVELOPELEN  6		/* RNS/Channel.py#MSGTYPE */

typedef char hmac_bound_fits[MAXBLOB <= HMAC_MAXMSG ? 1 : -1];

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
	int n = 0, lineno = 0;

	if ((f = fopen(path, "r")) == NULL)
		fatal("cannot open %s", path);

	while (readline(f, line, sizeof line, path, ++lineno)) {
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
	int n = 0, lineno = 0;

	if ((f = fopen(path, "r")) == NULL)
		fatal("cannot open %s", path);

	while (readline(f, line, sizeof line, path, ++lineno)) {
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
			fatal("%s: unusable field name on line %d", path, lineno);
		if (strlen(value) >= sizeof out[n].value)
			fatal("%s: value too long on line %d", path, lineno);

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
 * so the definition below carries its own prototype. It serves
 * crypto_sign_keypair a chosen seed and aborts on any other call; see
 * cmd/VENDOR, which says why that is what dump needs. */

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

static void dump_identity(struct blob *b)
{
	uint8_t hash[ADDRLEN];

	if (b[0].len != KEYSIZE)
		fatal("identity: public key is %zu bytes, expected %d", b[0].len, KEYSIZE);

	truncated_hash(b[0].data, KEYSIZE, hash, ADDRLEN);

	field_hex("public_key",     b[0].data, KEYSIZE);
	field_hex("x25519_public",  b[0].data, KEYHALF);
	field_hex("ed25519_public", b[0].data + KEYHALF, KEYHALF);
	field_hex("identity_hash",  hash, ADDRLEN);
}

static void dump_keyset(struct blob *b)
{
	uint8_t pub[KEYSIZE];
	uint8_t hash[ADDRLEN];

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

static void dump_destination(struct blob *b)
{
	uint8_t name_hash[NAMEHASHLEN];
	uint8_t material[NAMEHASHLEN + ADDRLEN];
	uint8_t dest_hash[ADDRLEN];
	size_t  matlen, start, i;

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

static void dump_signature(struct blob *b)
{
	const uint8_t *ed_pub;
	uint8_t digest[32];

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

static void dump_sign(struct blob *b)
{
	uint8_t pub[KEYHALF], sig[SIGLEN], digest[32];

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
static const char *xport_types[]  = { "broadcast", "transport" };

/* A rejection is the rule that was broken and its two numbers, named at
 * the line that decided. A parser fills one and returns 0; its caller
 * prints it and stops. See doc/fields, section Rejection. */
struct fault {
	const char *rule, *gotname, *needname;
	size_t got, need;
};

static int fault(struct fault *f, const char *rule,
                 const char *gotname, size_t got,
                 const char *needname, size_t need)
{
	f->rule = rule;
	f->gotname = gotname; f->got  = got;
	f->needname = needname; f->need = need;
	return 0;
}

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

static int parse_header(const uint8_t *raw, size_t len,
                        struct header *h, struct fault *f)
{
	size_t header_len;

	if (len < 2)
		return fault(f, "short-header", "length", len, "minimum_length", 2);

	h->flags = raw[0];
	h->hops  = raw[1];

	h->header_type      = (h->flags & 0x40) >> 6;
	h->context_flag     = (h->flags & 0x20) >> 5;
	h->transport_type   = (h->flags & 0x10) >> 4;
	h->destination_type = (h->flags & 0x0c) >> 2;
	h->packet_type      = (h->flags & 0x03);

	if (h->hops >= MAX_HOPS)
		return fault(f, "hop-limit", "hops", h->hops, "hop_limit", MAX_HOPS);

	header_len = 3 + ADDRLEN * (h->header_type + 1);
	if (len < header_len)
		return fault(f, "short-header", "length", len,
		             "minimum_length", header_len);

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

	return 1;
}

static int parse_announce(const struct header *h, struct announce *a,
                          struct fault *f)
{
	size_t minimum, at;

	minimum = KEYSIZE + NAMEHASHLEN + RANDHASHLEN + SIGLEN;
	if (h->context_flag == 1)
		minimum += RATCHETLEN;

	if (h->payload_len < minimum)
		return fault(f, "short-payload", "payload_length", h->payload_len,
		             "minimum_length", minimum);

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

	return 1;
}

/* The assembled material is payload_len - SIGLEN + ADDRLEN bytes: the
 * signature is in the payload and not in the signed data, the
 * destination hash the other way round. It fits in a MAXBLOB buffer
 * only because the signature is the larger of the two. */
typedef char signed_data_fits[ADDRLEN <= SIGLEN ? 1 : -1];

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

static void invalid(const char *rule, const char *gotname, size_t got,
                    const char *needname, size_t need)
{
	field("invalid", "%s", rule);
	field(gotname, "%zu", got);
	field(needname, "%zu", need);
}

static void print_fault(const struct fault *f)
{
	invalid(f->rule, f->gotname, f->got, f->needname, f->need);
}

static int open_packet(const struct blob *b, struct header *h)
{
	struct fault f;

	if (parse_header(b->data, b->len, h, &f))
		return 1;
	print_fault(&f);
	return 0;
}

static const struct {
	unsigned    byte;
	const char *name;
} contexts[] = {
	{ 0x00, "none" },
	{ 0x01, "resource" },
	{ 0x02, "resource_adv" },
	{ 0x03, "resource_req" },
	{ 0x04, "resource_hmu" },
	{ 0x05, "resource_prf" },
	{ 0x06, "resource_icl" },
	{ 0x07, "resource_rcl" },
	{ 0x09, "request" },
	{ 0x0a, "response" },
	{ 0x0b, "path_response" },
	{ 0x0e, "channel" },
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
	field_hex("app_data", a->app_data, a->app_data_len);
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
 * the two kinds do not share. RNS/Cryptography/Token.py#decrypt. */
struct token {
	const uint8_t *iv, *ciphertext, *mac;
	size_t   ctlen, ptlen;
	uint8_t  plain[MAXBLOB];
	int      mac_ok, opened, keyed;
};

static void token_open(const uint8_t *p, size_t len,
                       const uint8_t *key, size_t keylen, struct token *t)
{
	uint8_t expected[MACLEN], signed_part[MAXBLOB];
	/* The key splits in half whatever its length: signing first, then
	 * the cipher key, whose length is what selects AES-128 or AES-256.
	 * The hmac is 32 bytes either way, so the overhead does not move.
	 * RNS/Cryptography/Token.py#_signing_key. */
	size_t half = keylen / 2;

	t->iv         = p;
	t->ciphertext = p + IVLEN;
	t->ctlen      = len - TOKEN_OVERHEAD;
	t->mac        = p + len - MACLEN;
	t->ptlen      = 0;
	t->opened     = 0;
	t->mac_ok     = 0;
	t->keyed      = key != NULL;

	if (!t->keyed)
		return;

	memcpy(signed_part, t->iv, IVLEN);
	memcpy(signed_part + IVLEN, t->ciphertext, t->ctlen);
	hmac_sha256(key, half, signed_part, IVLEN + t->ctlen, expected);
	t->mac_ok = memcmp(t->mac, expected, MACLEN) == 0;

	if (t->mac_ok && t->ctlen > 0 && t->ctlen % 16 == 0 &&
	    aes_cbc_decrypt(key + half, half, t->iv, t->ciphertext, t->ctlen,
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
	field_hex("plaintext", t->plain, t->ptlen);
}

static void dump_encrypted(struct blob *b)
{
	struct header h;
	struct token t;
	const uint8_t *ephemeral;
	uint8_t pub[KEYSIZE], identity_hash[ADDRLEN];
	uint8_t agree[KEYHALF], shared[KEYHALF], derived[DERIVEDLEN];
	uint8_t ratchet_pub[KEYHALF];
	int agreed;

	if (b[0].len != KEYSIZE)
		fatal("encrypted: private key is %zu bytes, expected %d", b[0].len, KEYSIZE);
	if (!b[1].absent && b[1].len != KEYHALF)
		fatal("encrypted: ratchet key is %zu bytes, expected %d", b[1].len, KEYHALF);

	field_blob("recipient_private", &b[0]);
	field_blob("ratchet_private", &b[1]);

	if (!open_packet(&b[2], &h))
		return;

	if (h.payload_len < KEYHALF + TOKEN_OVERHEAD) {
		invalid("short-payload", "payload_length", h.payload_len,
		        "minimum_length", KEYHALF + TOKEN_OVERHEAD);
		return;
	}

	ephemeral = h.payload;

	/* The salt is the recipient's identity hash, derived from its own
	 * public key, even when the shared secret came from a ratchet.
	 * RNS/Identity.py#get_salt. */
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
	           agreed ? derived : NULL, DERIVEDLEN, &t);

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

static void dump_group(struct blob *b)
{
	struct header h;
	struct token t;
	size_t half;

	/* The one key in the corpus a human configures rather than a
	 * derivation produces, and the only place either token key length
	 * can turn up. Token takes only 64 or 32, and the
	 * length is what selects the cipher. RNS/Destination.py#GROUP. */
	if (b[0].len != DERIVEDLEN && b[0].len != DERIVEDLEN / 2)
		fatal("group: group key is %zu bytes, expected %d or %d",
		      b[0].len, DERIVEDLEN, DERIVEDLEN / 2);
	half = b[0].len / 2;

	field_blob("group_key", &b[0]);

	if (!open_packet(&b[1], &h))
		return;

	if (h.payload_len < TOKEN_OVERHEAD) {
		invalid("short-payload", "payload_length", h.payload_len,
		        "minimum_length", TOKEN_OVERHEAD);
		return;
	}

	token_open(h.payload, h.payload_len, b[0].data, b[0].len, &t);

	print_header(&h);
	print_token(&t);
	field_hex("signing_key", b[0].data, half);
	field_hex("encryption_key", b[0].data + half, half);
	print_plaintext(&t);
}

static void dump_announce(struct blob *b)
{
	struct header h;
	struct announce a;
	struct fault f;


	if (!parse_header(b[0].data, b[0].len, &h, &f) ||
	    !parse_announce(&h, &a, &f)) {
		print_fault(&f);
		return;
	}

	print_announce(&h, &a);
}

static void dump_plain(struct blob *b)
{
	struct header h;


	if (!open_packet(&b[0], &h))
		return;

	print_header(&h);
	field("plaintext_length", "%zu", h.payload_len);
	field_hex("plaintext", h.payload, h.payload_len);
}

static void dump_pathrequest(struct blob *b)
{
	struct header h;
	size_t taglen;
	const uint8_t *wanted, *requester, *tag;
	uint8_t unique[ADDRLEN * 2];


	if (!open_packet(&b[0], &h))
		return;

	if (h.payload_len < ADDRLEN) {
		invalid("short-payload", "payload_length", h.payload_len,
		        "minimum_length", ADDRLEN);
		return;
	}

	wanted = h.payload;
	if (h.payload_len > ADDRLEN * 2) {
		requester = h.payload + ADDRLEN;
		tag       = h.payload + ADDRLEN * 2;
		taglen    = h.payload_len - ADDRLEN * 2;
	} else {
		requester = NULL;
		tag       = h.payload + ADDRLEN;
		taglen    = h.payload_len - ADDRLEN;
	}

	print_header(&h);
	field_hex("wanted_hash", wanted, ADDRLEN);
	if (requester != NULL)
		field_hex("requester_id", requester, ADDRLEN);
	else
		field("requester_id", "-");
	field_hex("tag", tag, taglen);

	/* Only the first 16 bytes of the tag reach the duplicate check, so
	 * two requests that differ past that are one request. */
	if (taglen > 0) {
		memcpy(unique, wanted, ADDRLEN);
		memcpy(unique + ADDRLEN, tag, taglen < ADDRLEN ? taglen : ADDRLEN);
		field_hex("unique_tag", unique,
		          ADDRLEN + (taglen < ADDRLEN ? taglen : ADDRLEN));
	} else {
		field("unique_tag", "-");
	}
	field("accepted", "%s", taglen > 0 ? "yes" : "no");
}

static size_t hashable_part(const uint8_t *raw, size_t len,
                            const struct header *h, uint8_t *out)
{
	size_t from = h->header_type ? 2 + ADDRLEN : 2;

	out[0] = raw[0] & 0x0f;
	memcpy(out + 1, raw + from, len - from);
	return 1 + len - from;
}

static void link_id_of(const uint8_t *raw, size_t len,
                       const struct header *h, uint8_t *out)
{
	uint8_t part[MAXBLOB];
	size_t n = hashable_part(raw, len, h, part);

	if (h->payload_len > ECPUBSIZE)
		n -= h->payload_len - ECPUBSIZE;

	truncated_hash(part, n, out, ADDRLEN);
}

static void packet_hash_of(const uint8_t *raw, size_t len,
                           const struct header *h, uint8_t out[32])
{
	uint8_t part[MAXBLOB];

	sha256(part, hashable_part(raw, len, h, part), out);
}

static void print_signalling(const uint8_t *p)
{
	unsigned value = 0, mode = MODE_DEFAULT;

	if (p != NULL) {
		value = (unsigned)p[0] << 16 | (unsigned)p[1] << 8 | p[2];
		mode  = (value >> 21) & 0x07;
		field_hex("signalling", p, SIGNALLEN);
	} else {
		field("signalling", "-");
	}

	if (mode == MODE_DEFAULT)
		field("mode", "aes256_cbc");
	else
		field("mode", "%02x", mode);

	if (p != NULL)
		field("mtu", "%u", value & MTU_BYTEMASK);
	else
		field("mtu", "-");
}

static void dump_linkrequest(struct blob *b)
{
	struct header h;
	uint8_t link_id[ADDRLEN];
	int signalled;


	if (!open_packet(&b[0], &h))
		return;

	signalled = h.payload_len == ECPUBSIZE + SIGNALLEN;
	if (!signalled && h.payload_len != ECPUBSIZE) {
		field("invalid", "invalid-length");
		field("payload_length", "%zu", h.payload_len);
		field("accepted_length", "%d", ECPUBSIZE);
		field("signalled_length", "%d", ECPUBSIZE + SIGNALLEN);
		return;
	}

	link_id_of(b[0].data, b[0].len, &h, link_id);

	print_header(&h);
	field_hex("x25519_public", h.payload, KEYHALF);
	field_hex("ed25519_public", h.payload + KEYHALF, KEYHALF);
	print_signalling(signalled ? h.payload + ECPUBSIZE : NULL);
	field_hex("link_id", link_id, ADDRLEN);
}

static void dump_linkproof(struct blob *b)
{
	struct header h, rh;
	struct fault f;
	size_t sdlen = 0;
	const uint8_t *signature, *x25519, *signalling, *signer;
	uint8_t link_id[ADDRLEN], signed_data[MAXBLOB];
	int signalled;

	if (b[1].len != KEYSIZE)
		fatal("linkproof: identity key is %zu bytes, expected %d", b[1].len, KEYSIZE);

	field_blob("link_request", &b[0]);
	field_blob("signer_public", &b[1]);

	if (!parse_header(b[0].data, b[0].len, &rh, &f))
		fatal("linkproof: the link request does not decode");

	if (!open_packet(&b[2], &h))
		return;

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
	print_signalling(signalled ? signalling : NULL);
	field_hex("signer_ed25519", signer, KEYHALF);
	field_hex("signed_data", signed_data, sdlen);
	field("signature_valid", "%s",
	      ed25519_verify(signer, signature, signed_data, sdlen) ? "yes" : "no");
}

/* Enough msgpack to read what the reference puts on a link. Every type
 * outside that set is refused, and a refusal sets bad rather than
 * ending the program: a reader that stops in the middle prints half a
 * record, which doc/harness rule 6 forbids and which dump is the
 * template for. Once bad is set nothing further is read and every
 * remaining field prints "-".
 *
 * There is no check for bytes after the value, because the reference
 * has none. umsgpack.unpackb returns the value and discards the rest,
 * and every call site hands it the whole plaintext.
 *
 *	RNS/vendor/umsgpack.py#_pack2, RNS/Link.py#unpacked_request,
 *	RNS/Resource.py#unpack
 */
struct mp {
	const uint8_t *p;
	size_t         left;
	int            bad;
};

static unsigned mp_head(struct mp *m)
{
	if (m->bad || m->left == 0) {
		m->bad = 1;
		return 0xc1;
	}
	m->left--;
	return *m->p++;
}

static const uint8_t *mp_take(struct mp *m, size_t n)
{
	const uint8_t *at = m->p;

	if (m->bad || m->left < n) {
		m->bad = 1;
		return NULL;
	}
	m->p    += n;
	m->left -= n;
	return at;
}

static uint64_t mp_be(const uint8_t *p, size_t n)
{
	uint64_t v = 0;
	size_t   i;

	if (p == NULL)
		return 0;
	for (i = 0; i < n; i++)
		v = v << 8 | p[i];
	return v;
}

static size_t mp_array(struct mp *m)
{
	unsigned h = mp_head(m);

	if ((h & 0xf0) != 0x90)
		m->bad = 1;
	return h & 0x0f;
}

static size_t mp_map(struct mp *m)
{
	unsigned h = mp_head(m);

	/* Sixteen pairs is where the count leaves the head byte, and an
	 * advertisement of eleven keys reaches that with five pairs this
	 * reader has no field for. The 32-bit width needs more pairs than
	 * a packet holds bytes. RNS/vendor/umsgpack.py#_pack_map. */
	if ((h & 0xf0) == 0x80)
		return h & 0x0f;
	if (h == 0xde)
		return (size_t)mp_be(mp_take(m, 2), 2);

	m->bad = 1;
	return 0;
}

static void mp_skip_head(struct mp *m, unsigned h)
{
	size_t n;

	/* Every type umsgpack writes, so that a pair this reader does not
	 * want can be stepped over to reach the next one. The reference
	 * unpacks the whole map before it looks a name up, so a value this
	 * reader has no field for must still leave the eleven readable.
	 * RNS/vendor/umsgpack.py#_unpack.
	 *
	 * Five widths are absent because no packet holds one: str32, bin32,
	 * ext32 and the two 32-bit container headers each need more than
	 * 65535 bytes or elements. So is float32, which umsgpack writes
	 * only for a caller that forces single precision.
	 * RNS/vendor/umsgpack.py#_pack_float. */
	if (h < 0x80 || h >= 0xe0)                 return;	/* fixint */
	if (h == 0xc0 || h == 0xc2 || h == 0xc3)   return;	/* nil, bool */
	if ((h & 0xe0) == 0xa0) { mp_take(m, h & 0x1f); return; }
	if (h == 0xcc || h == 0xd0) { mp_take(m, 1); return; }
	if (h == 0xcd || h == 0xd1) { mp_take(m, 2); return; }
	if (h == 0xce || h == 0xd2) { mp_take(m, 4); return; }
	if (h == 0xcf || h == 0xd3 || h == 0xcb) { mp_take(m, 8); return; }
	if (h == 0xc4 || h == 0xd9) { mp_take(m, (size_t)mp_be(mp_take(m, 1), 1)); return; }
	if (h == 0xc5 || h == 0xda) { mp_take(m, (size_t)mp_be(mp_take(m, 2), 2)); return; }

	/* An ext value is a bin value with a type byte in front of its
	 * body, and umsgpack writes one for any Ext a caller packs. The
	 * five fixext widths write their length in the head byte, as a
	 * power of two and not as the low bits, so they are the one width
	 * class here that is neither counted nor read. The type byte is
	 * outside the length either way, which is the byte a reader that
	 * measures an ext as a bin is short by.
	 * RNS/vendor/umsgpack.py#_pack_ext. */
	if (h >= 0xd4 && h <= 0xd8) { mp_take(m, 1 + ((size_t)1 << (h - 0xd4))); return; }
	if (h == 0xc7) { mp_take(m, 1 + (size_t)mp_be(mp_take(m, 1), 1)); return; }

	/* A container is stepped over element by element, and a map counts
	 * twice because its pairs are two elements each. The recursion goes
	 * no deeper than the plaintext is long: every level reads a header
	 * byte of its own before it descends. */
	if      ((h & 0xf0) == 0x90) n =     h & 0x0f;
	else if ((h & 0xf0) == 0x80) n = 2 * (h & 0x0f);
	else if (h == 0xdc)          n =     (size_t)mp_be(mp_take(m, 2), 2);
	else if (h == 0xde)          n = 2 * (size_t)mp_be(mp_take(m, 2), 2);
	else { m->bad = 1; return; }

	while (n-- > 0 && !m->bad)
		mp_skip_head(m, mp_head(m));
}

static void mp_skip(struct mp *m)
{
	mp_skip_head(m, mp_head(m));
}

static char mp_key(struct mp *m)
{
	unsigned       h = mp_head(m);
	const uint8_t *p;

	/* The reference looks each of the eleven names up in the map it
	 * unpacked, so a key it has no name for is stepped over with its
	 * value and the keys after it still read.
	 * RNS/Resource.py#unpack. Only a one-byte string can be one of the
	 * eleven; every other key is skipped here and reported as none,
	 * which is what the caller does with a name it does not know. */
	if (h != 0xa1) {
		mp_skip_head(m, h);
		return '\0';
	}
	p = mp_take(m, 1);
	return p != NULL ? (char)*p : '\0';
}

static uint64_t mp_uint(struct mp *m)
{
	unsigned h = mp_head(m);

	if (h < 0x80)  return h;
	if (h == 0xcc) return mp_be(mp_take(m, 1), 1);
	if (h == 0xcd) return mp_be(mp_take(m, 2), 2);
	if (h == 0xce) return mp_be(mp_take(m, 4), 4);
	m->bad = 1;
	return 0;
}

static const uint8_t *mp_bin(struct mp *m, size_t *len)
{
	unsigned h = mp_head(m);

	*len = 0;
	if (h == 0xc0) return NULL;
	if (h == 0xc4) { *len = (size_t)mp_be(mp_take(m, 1), 1); return mp_take(m, *len); }
	if (h == 0xc5) { *len = (size_t)mp_be(mp_take(m, 2), 2); return mp_take(m, *len); }
	m->bad = 1;
	return NULL;
}

static const uint8_t *mp_double(struct mp *m)
{
	if (mp_head(m) != 0xcb)
		m->bad = 1;
	return mp_take(m, 8);
}

static void mp_field_uint(struct mp *m, const char *name, const char *fmt)
{
	uint64_t v = mp_uint(m);

	if (m->bad)
		field(name, "-");
	else
		field(name, fmt, (unsigned long long)v);
}

static void mp_field_bin(struct mp *m, const char *name)
{
	size_t         n;
	const uint8_t *p = mp_bin(m, &n);

	if (m->bad)
		field(name, "-");
	else
		field_hex(name, p, n);
}

static void mp_field_double(struct mp *m, const char *name)
{
	const uint8_t *p = mp_double(m);

	if (m->bad)
		field(name, "-");
	else
		field_hex(name, p, 8);
}

#define RESOURCE     0x01
#define RESOURCE_ADV 0x02
#define RESOURCE_REQ 0x03
#define RESOURCE_HMU 0x04
#define RESOURCE_ICL 0x06
#define RESOURCE_RCL 0x07
#define MAPHASHLEN   4		/* RNS/Resource.py#MAPHASH_LEN */
#define HASHLEN      32		/* RNS/Identity.py#HASHLENGTH */
#define EXHAUSTED    0xff	/* RNS/Resource.py#HASHMAP_IS_EXHAUSTED */

static int short_plaintext(size_t len, size_t need)
{
	if (len >= need)
		return 0;

	field("invalid", "short-plaintext");
	field("minimum_length", "%zu", need);
	return 1;
}

static void print_resource(unsigned context, const uint8_t *p, size_t len)
{
	static const char order[] = "tdnhroilqfm";
	struct mp m = { p, len, 0 };
	size_t i;

	if (context == RESOURCE_ADV) {
		/* The reference reads this map by key and not by position:
		 * unpack names all eleven, in an order that is not the one
		 * pack writes them in, so neither the order nor the count is
		 * a rule of the format. RNS/Resource.py#unpack.
		 *
		 * Each key is therefore located first and the fields are
		 * printed in the corpus's own order afterwards. A key that is
		 * not there leaves its stream bad and prints "-", which is
		 * what a value the reader never reached prints everywhere
		 * else. A twelfth key is the same rule read the other way: it
		 * has no field here and takes nothing from the eleven that
		 * do. */
		struct mp value[sizeof order - 1];
		size_t pairs = mp_map(&m);
		int    twice = 0;

		for (i = 0; i < sizeof order - 1; i++) {
			value[i].p    = NULL;
			value[i].left = 0;
			value[i].bad  = 1;
		}

		for (i = 0; i < pairs && !m.bad; i++) {
			char        key = mp_key(&m);
			const char *at  = key != '\0' ? strchr(order, key) : NULL;

			if (at != NULL) {
				if (!value[at - order].bad)
					twice = 1;
				value[at - order]     = m;
				value[at - order].bad = 0;
			}
			mp_skip(&m);
		}

		/* A map is whole or it is nothing, which is where this differs
		 * from an array body: umsgpack builds the dictionary or
		 * raises, and unpack looks eleven names up in what it built.
		 * A map that names one key twice and a map the plaintext ran
		 * out of are both nothing, and every field is the dash that
		 * says so, which is what a plaintext that is no map at all
		 * prints. RNS/vendor/umsgpack.py#DuplicateKeyException,
		 * RNS/vendor/umsgpack.py#InsufficientDataException. */
		if (twice || m.bad)
			for (i = 0; i < sizeof order - 1; i++)
				value[i].bad = 1;

		for (i = 0; order[i] != '\0'; i++) {
			struct mp *v = &value[i];

			switch (order[i]) {
			case 't': mp_field_uint(v, "transfer_size",  "%llu");   break;
			case 'd': mp_field_uint(v, "data_size",      "%llu");   break;
			case 'n': mp_field_uint(v, "resource_parts", "%llu");   break;
			case 'i': mp_field_uint(v, "segment_index",  "%llu");   break;
			case 'l': mp_field_uint(v, "total_segments", "%llu");   break;
			case 'f': mp_field_uint(v, "resource_flags", "%02llx"); break;
			case 'h': mp_field_bin(v, "resource_hash");   break;
			case 'r': mp_field_bin(v, "resource_random"); break;
			case 'o': mp_field_bin(v, "original_hash");   break;
			case 'q': mp_field_bin(v, "request_id");      break;
			case 'm': mp_field_bin(v, "hashmap");         break;
			}
		}
		return;
	}

	if (context == RESOURCE_REQ) {
		size_t at = 1;
		int exhausted;

		/* The flag decides how much follows it, so it is read only
		 * after the byte holding it is known to be there. It is one
		 * value and not a boolean: the reference compares the byte
		 * against HASHMAP_IS_EXHAUSTED, so every other byte, 0x01
		 * included, says the hashmap is not exhausted. */
		if (short_plaintext(len, 1))
			return;
		exhausted = p[0] == EXHAUSTED;
		if (short_plaintext(len, 1 + (exhausted ? MAPHASHLEN : 0) + HASHLEN))
			return;

		field("hashmap_exhausted", "%s", exhausted ? "yes" : "no");
		if (exhausted) {
			field_hex("last_map_hash", p + at, MAPHASHLEN);
			at += MAPHASHLEN;
		} else {
			field("last_map_hash", "-");
		}
		field_hex("resource_hash", p + at, HASHLEN);
		field_hex("requested_hashes", p + at + HASHLEN,
		          len - at - HASHLEN);
		return;
	}

	if (context == RESOURCE_HMU) {
		struct mp u = { NULL, 0, 0 };

		/* The hash is fixed width and the msgpack array follows it, so
		 * one byte past the hash is the least that can be read. */
		if (short_plaintext(len, HASHLEN + 1))
			return;

		u.p    = p + HASHLEN;
		u.left = len - HASHLEN;

		if (mp_array(&u) != 2)
			u.bad = 1;
		field_hex("resource_hash", p, HASHLEN);
		mp_field_uint(&u, "segment_index", "%llu");
		mp_field_bin(&u, "hashmap");
		return;
	}

	if (context == RESOURCE_ICL || context == RESOURCE_RCL)
		field_hex("resource_hash", p, len);
}

static void dump_linkdata(struct blob *b)
{
	struct header h, rh;
	struct token t;
	struct fault f;
	const uint8_t *initiator_public;
	uint8_t link_id[ADDRLEN], shared[KEYHALF], derived[DERIVEDLEN];
	uint8_t identity_hash[ADDRLEN], signed_data[ADDRLEN + KEYSIZE];
	int agreed;

	if (b[1].len != KEYHALF)
		fatal("linkdata: private key is %zu bytes, expected %d", b[1].len, KEYHALF);

	field_blob("link_request", &b[0]);
	field_blob("responder_private", &b[1]);

	if (!parse_header(b[0].data, b[0].len, &rh, &f))
		fatal("linkdata: the link request does not decode");

	if (!open_packet(&b[2], &h))
		return;

	link_id_of(b[0].data, b[0].len, &rh, link_id);

	print_header(&h);
	field_hex("link_id", link_id, ADDRLEN);
	field("link_id_match", "%s",
	      memcmp(h.destination_hash, link_id, ADDRLEN) == 0 ? "yes" : "no");

	/* A resource part is not encrypted by the packet layer either. The
	 * resource encrypted its whole data through the link once and cut
	 * the token into parts, so only the first part carries an iv and
	 * only the last carries an hmac, and no part opens on its own.
	 * RNS/Resource.py#link.encrypt, RNS/Packet.py#RESOURCE. */
	if (h.context == RESOURCE) {
		field("encrypted", "no");
		field("plaintext_length", "%zu", h.payload_len);
		field_hex("plaintext", h.payload, h.payload_len);
		return;
	}

	/* Keepalives carry no data and are the one link packet the
	 * reference does not encrypt. RNS/Packet.py#KEEPALIVE. */
	if (h.context == 0xfa) {
		field("encrypted", "no");
		field("plaintext_length", "%zu", h.payload_len);
		field_hex("plaintext", h.payload, h.payload_len);
		return;
	}

	field("encrypted", "yes");

	if (h.payload_len < TOKEN_OVERHEAD) {
		invalid("short-payload", "payload_length", h.payload_len,
		        "minimum_length", TOKEN_OVERHEAD);
		return;
	}

	/* Both ends already hold the shared secret, so no packet on the
	 * link carries an ephemeral key. The salt is the link id, which is
	 * in no packet either. RNS/Link.py#shared_key,
	 * RNS/Link.py#get_salt. */
	initiator_public = rh.payload;
	agreed = x25519_shared(shared, b[1].data, initiator_public);
	if (agreed)
		hkdf_sha256(shared, KEYHALF, link_id, ADDRLEN, NULL, 0,
		            derived, DERIVEDLEN);
	token_open(h.payload, h.payload_len, agreed ? derived : NULL, DERIVEDLEN, &t);

	print_token(&t);
	print_keys(agreed ? shared : NULL, derived);
	print_plaintext(&t);
	if (!t.opened)
		return;

	/* A channel envelope is six bytes of big-endian header and then the
	 * message. The length it declares is not read back: Envelope.unpack
	 * takes everything after the six bytes. RNS/Channel.py#unpack. */
	if (h.context == 0x0e) {
		if (short_plaintext(t.ptlen, ENVELOPELEN))
			return;
		field_hex("msgtype", t.plain, 2);
		field("sequence", "%u", (unsigned)(t.plain[2] << 8 | t.plain[3]));
		field("declared_length", "%u", (unsigned)(t.plain[4] << 8 | t.plain[5]));
		field_hex("message", t.plain + ENVELOPELEN, t.ptlen - ENVELOPELEN);
	}

	/* A request is a three-element array and a response a two-element
	 * one, both msgpack, both with no length or type byte of their own
	 * around them. RNS/Link.py#unpacked_request,
	 * RNS/Link.py#packed_response. */
	if (h.context == 0x09 || h.context == 0x0a) {
		struct mp m = { t.plain, t.ptlen, 0 };

		/* An empty plaintext carries not even the array header, and
		 * that is a length rule the corpus names. Everything shorter
		 * than the array it announces is msgpack's own business and
		 * prints as dashes. */
		if (short_plaintext(t.ptlen, 1))
			return;

		if (h.context == 0x09) {
			if (mp_array(&m) != 3)
				m.bad = 1;
			mp_field_double(&m, "request_time");
			mp_field_bin(&m, "request_path_hash");
			mp_field_bin(&m, "request_data");
		} else {
			if (mp_array(&m) != 2)
				m.bad = 1;
			mp_field_bin(&m, "request_id");
			mp_field_bin(&m, "response_data");
		}
	}

	if (t.opened)
		print_resource(h.context, t.plain, t.ptlen);

	/* An identify proof names the initiator, which nothing else on a
	 * link does. Its signature covers the link id, so it cannot be
	 * replayed onto another link. RNS/Link.py#signed_data. */
	if (t.opened && h.context == 0xfb) {
		/* The length is a rule and not a bound. Both fields are read
		 * at fixed offsets, so a plaintext of any other length names
		 * nobody and the reference tests for the one number rather
		 * than for enough bytes. RNS/Link.py#LINKIDENTIFY. */
		if (t.ptlen != KEYSIZE + SIGLEN) {
			field("invalid", "identify-length");
			field("required_length", "%d", KEYSIZE + SIGLEN);
			return;
		}

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

static void dump_proof(struct blob *b)
{
	struct header h, ph;
	struct fault f;
	const uint8_t *signature, *signer;
	uint8_t packet_hash[32];
	int explicit_form, on_link;

	if (b[1].len != KEYSIZE && b[1].len != KEYHALF)
		fatal("proof: signer key is %zu bytes, expected %d or %d",
		      b[1].len, KEYSIZE, KEYHALF);

	field_blob("proved_packet", &b[0]);
	field_blob("signer_public", &b[1]);

	if (!parse_header(b[0].data, b[0].len, &ph, &f))
		fatal("proof: the proved packet does not decode");

	if (!open_packet(&b[2], &h))
		return;

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

	/* On a link the proof is addressed to the link id rather than to
	 * the hash it proves, and the key that verifies it is a single
	 * Ed25519 public rather than the two halves of an identity. Which
	 * of the two applies is in the flags byte and nowhere else. */
	on_link = h.destination_type == 3;

	/* Which half is the signing key follows from the flags, and the two
	 * forms take keys of two lengths. A key of the wrong length here
	 * would verify against the X25519 half and print signature_valid
	 * no, which is a wrong field value where a message will do. */
	if (b[1].len != (on_link ? (size_t)KEYHALF : (size_t)KEYSIZE))
		fatal("proof: %s takes a %d-byte key, got %zu",
		      on_link ? "a proof on a link" : "a proof to a destination",
		      on_link ? KEYHALF : KEYSIZE, b[1].len);

	signer  = on_link ? b[1].data : b[1].data + KEYHALF;

	print_header(&h);
	field("form", "%s", explicit_form ? "explicit" : "implicit");
	field_hex("packet_hash", packet_hash, sizeof packet_hash);
	if (explicit_form)
		field_hex("proof_hash", h.payload, 32);
	else
		field("proof_hash", "-");
	field("hash_match", "%s",
	      !explicit_form || memcmp(h.payload, packet_hash, 32) == 0 ? "yes" : "no");
	if (on_link) {
		field_hex("link_id", ph.destination_hash, ADDRLEN);
		field("link_id_match", "%s",
		      memcmp(h.destination_hash, ph.destination_hash, ADDRLEN) == 0
		      ? "yes" : "no");
	} else {
		field_hex("proof_destination", packet_hash, ADDRLEN);
		field("destination_match", "%s",
		      memcmp(h.destination_hash, packet_hash, ADDRLEN) == 0 ? "yes" : "no");
	}
	field_hex("signature", signature, SIGLEN);
	field_hex("signer_ed25519", signer, KEYHALF);
	field("signature_valid", "%s",
	      ed25519_verify(signer, signature, packet_hash, sizeof packet_hash) ? "yes" : "no");
}

static void dump_resourceproof(struct blob *b)
{
	struct header h;

	if (b[0].len != HASHLEN)
		fatal("resourceproof: resource hash is %zu bytes, expected %d",
		      b[0].len, HASHLEN);

	field_blob("advertised_hash", &b[0]);

	if (!open_packet(&b[1], &h))
		return;

	print_header(&h);

	if (h.payload_len != 2 * HASHLEN) {
		field("invalid", "invalid-length");
		field("payload_length", "%zu", h.payload_len);
		field("accepted_length", "%d", 2 * HASHLEN);
		return;
	}

	field_hex("resource_hash", h.payload, HASHLEN);
	field_hex("resource_proof", h.payload + HASHLEN, HASHLEN);
	field("hash_match", "%s",
	      memcmp(h.payload, b[0].data, HASHLEN) == 0 ? "yes" : "no");
}

/* RNS/Reticulum.py#IFAC_SALT. */
static const uint8_t ifac_salt[32] = {
	0xad,0xf5,0x4d,0x88,0x2c,0x9a,0x9b,0x80,
	0x77,0x1e,0xb4,0x99,0x5d,0x70,0x2d,0x4a,
	0x3e,0x73,0x33,0x91,0xb2,0xa0,0xf5,0x3f,
	0x41,0x6d,0x9f,0x90,0x7e,0x55,0xcf,0xf8,
};

static size_t ifac_origin(const struct blob *netname, const struct blob *netkey,
                          uint8_t *out)
{
	size_t n = 0;

	if (!netname->absent) {
		sha256(netname->data, netname->len, out);
		n += 32;
	}
	if (!netkey->absent) {
		sha256(netkey->data, netkey->len, out + n);
		n += 32;
	}
	return n;
}

static void ifac_key(const uint8_t *origin, size_t originlen, uint8_t key[KEYSIZE])
{
	uint8_t hash[32];

	sha256(origin, originlen, hash);
	hkdf_sha256(hash, sizeof hash, ifac_salt, sizeof ifac_salt, NULL, 0,
	            key, KEYSIZE);
}

static void ifac_mask(const uint8_t *ifac, size_t ifac_size,
                      const uint8_t key[KEYSIZE],
                      const uint8_t *in, size_t len, uint8_t *out)
{
	static uint8_t mask[MAXBLOB];
	size_t i;

	if (len > MAXBLOB)
		fatal("frame of %zu bytes exceeds %d", len, MAXBLOB);

	hkdf_sha256(ifac, ifac_size, key, KEYSIZE, NULL, 0, mask, len);

	for (i = 0; i < len; i++) {
		if (i <= 1 || i > ifac_size + 1)
			out[i] = in[i] ^ mask[i];
		else
			out[i] = in[i];
	}
}

static void dump_ifac(struct blob *b)
{
	static uint8_t unmasked[MAXBLOB], packet[MAXBLOB];
	const uint8_t *ifac;
	uint8_t origin[KEYSIZE], key[KEYSIZE], expected[SIGLEN];
	size_t originlen, ifac_size, plen;

	if (b[0].absent && b[1].absent)
		fatal("ifac: neither a network name nor a passphrase");
	if (b[2].len != 1)
		fatal("ifac: access code size is %zu bytes, expected 1", b[2].len);

	ifac_size = b[2].data[0];
	/* Both bounds. The lower one is the reference's own: a configuration
	 * below IFAC_MIN_SIZE is not accepted, and doc/packet says so. It is
	 * checked here because the access code is what hkdf derives the mask
	 * from, and hkdf aborts on an empty input rather than reporting it.
	 * RNS/Reticulum.py#IFAC_MIN_SIZE. */
	if (ifac_size < 1)
		fatal("ifac: access code of %zu bytes is below the minimum of 1",
		      ifac_size);
	if (ifac_size > SIGLEN)
		fatal("ifac: access code of %zu bytes exceeds the signature", ifac_size);
	if (b[3].len <= 2 + ifac_size)
		fatal("ifac: frame of %zu bytes holds no packet", b[3].len);

	originlen = ifac_origin(&b[0], &b[1], origin);
	ifac_key(origin, originlen, key);

	ifac = b[3].data + 2;
	ifac_mask(ifac, ifac_size, key, b[3].data, b[3].len, unmasked);

	/* The access code is not part of the packet, and the flag that
	 * announced it is cleared before the signature is checked. */
	plen = b[3].len - ifac_size;
	packet[0] = unmasked[0] & 0x7f;
	packet[1] = unmasked[1];
	memcpy(packet + 2, unmasked + 2 + ifac_size, plen - 2);

	ed25519_sign(key + KEYHALF, packet, plen, expected);

	field_blob("netname", &b[0]);
	field_blob("netkey", &b[1]);
	field_hex("ifac_origin", origin, originlen);
	field_hex("ifac_key", key, KEYSIZE);
	field("ifac_size", "%zu", ifac_size);
	field("frame_length", "%zu", b[3].len);
	field_hex("ifac", ifac, ifac_size);
	field_hex("packet", packet, plen);
	field_hex("expected_ifac", expected + SIGLEN - ifac_size, ifac_size);
	field("ifac_valid", "%s",
	      memcmp(ifac, expected + SIGLEN - ifac_size, ifac_size) == 0 ? "yes" : "no");
}

/* Rebuilding raw from expect. A vector of the encode class is one whose
 * expect holds every byte of raw, and cmd/check tests that claim by
 * diffing the result. A field whose value is "-" contributes no bytes,
 * which is how the format spells every optional field, and it is why
 * this direction needs no conditions where the decoders have several.
 *
 * The table this runs from is the encoders' own; CLAUDE.md says why it
 * is not shared with the decoders. What keeps the two directions from
 * drifting apart is the round trip: a field dropped here, or moved,
 * stops reproducing raw for every vector of the kind. */

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

static void emit_field(struct kv *f, int n, const char *name)
{
	printf("%s\n", lookup(f, n, name));
}

static void encode_layout(const char *layout, struct kv *f, int n)
{
	struct out o = { "", 0 };
	char buf[256], *name;
	int packing = 0;

	if (strlen(layout) >= sizeof buf)
		fatal("layout longer than %zu bytes", sizeof buf - 1);
	strcpy(buf, layout);

	for (name = strtok(buf, " "); name != NULL; name = strtok(NULL, " ")) {
		if (strcmp(name, "=") == 0) {
			put_header(&o, f, n);
			packing = 1;
		} else if (packing) {
			put_field(&o, f, n, name);
		} else {
			emit_field(f, n, name);
		}
	}

	if (packing)
		emit(&o);
}

static void get_blob(struct kv *f, int n, const char *name, struct blob *b)
{
	const char *v = lookup(f, n, name);

	b->len = 0;
	b->absent = strcmp(v, "-") == 0;
	if (!b->absent)
		decode_hex(b, v, strlen(v), name);
}

static void encode_ifac(struct kv *f, int n)
{
	static uint8_t packet[MAXBLOB], frame[MAXBLOB], masked[MAXBLOB];
	struct blob netname, netkey, code, pkt;
	uint8_t origin[KEYSIZE], key[KEYSIZE];
	struct out o = { "", 0 };
	size_t len, originlen;

	get_blob(f, n, "netname", &netname);
	get_blob(f, n, "netkey", &netkey);
	get_blob(f, n, "ifac", &code);
	get_blob(f, n, "packet", &pkt);

	if (pkt.len < 2)
		fatal("ifac: packet of %zu bytes has no header", pkt.len);
	/* The same two bounds the decoder applies, and for the same reason:
	 * an absent code reaches hkdf as an empty input. */
	if (code.len < 1)
		fatal("ifac: access code of %zu bytes is below the minimum of 1",
		      code.len);
	if (code.len > SIGLEN)
		fatal("ifac: access code of %zu bytes exceeds the signature", code.len);

	len = pkt.len + code.len;
	if (len > MAXBLOB)
		fatal("ifac: frame of %zu bytes exceeds %d", len, MAXBLOB);

	originlen = ifac_origin(&netname, &netkey, origin);
	ifac_key(origin, originlen, key);

	memcpy(packet, pkt.data, pkt.len);

	frame[0] = packet[0] | 0x80;
	frame[1] = packet[1];
	memcpy(frame + 2, code.data, code.len);
	memcpy(frame + 2 + code.len, packet + 2, pkt.len - 2);

	ifac_mask(code.data, code.len, key, frame, len, masked);
	masked[0] |= 0x80;

	emit_field(f, n, "netname");
	emit_field(f, n, "netkey");
	put_byte(&o, (unsigned)code.len);
	emit(&o);

	put_bytes(&o, masked, len);
	emit(&o);
}

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

/* Every kind, and for each the two directions. A kind with neither a
 * layout nor an encoder is one no vector can claim the encode class
 * for: its raw holds something expect does not record.
 *
 * blobs is how many lines the kind's raw holds. It is checked here
 * rather than in each decoder because a decoder that has to count its
 * own arguments before reading them is a decoder that can forget to. */
static const struct {
	const char *name;
	int blobs;
	void (*decode)(struct blob *);
	void (*encode)(struct kv *, int);	/* where a layout will not do */
	const char *layout;
} kinds[] = {
	{ "identity",    1, dump_identity,    NULL, "public_key" },
	{ "keyset",      1, dump_keyset,      NULL, "private_key" },
	{ "destination", 2, dump_destination, NULL, "name identity_hash" },
	{ "signature",   3, dump_signature,   NULL, NULL },
	{ "sign",        2, dump_sign,        NULL, NULL },
	{ "announce",    1, dump_announce,    NULL,
	  "= public_key name_hash random_hash ratchet signature app_data" },
	{ "plain",       1, dump_plain,       NULL, "= plaintext" },
	{ "pathrequest", 1, dump_pathrequest, NULL, "= wanted_hash requester_id tag" },
	{ "encrypted",   3, dump_encrypted,   NULL,
	  "recipient_private ratchet_private = ephemeral_public iv ciphertext hmac" },
	{ "group",       2, dump_group,       NULL, "group_key = iv ciphertext hmac" },
	{ "linkrequest", 1, dump_linkrequest, NULL,
	  "= x25519_public ed25519_public signalling" },
	{ "linkproof",   3, dump_linkproof,   NULL,
	  "link_request signer_public = signature x25519_public signalling" },
	{ "linkdata",    3, dump_linkdata,    encode_linkdata, NULL },
	{ "proof",       3, dump_proof,       NULL,
	  "proved_packet signer_public = proof_hash signature" },
	{ "resourceproof", 2, dump_resourceproof, NULL,
	  "advertised_hash = resource_hash resource_proof" },
	{ "ifac",        4, dump_ifac,        encode_ifac, NULL },
};

int main(int argc, char **argv)
{
	static struct blob blobs[MAXBLOBS];
	static struct kv fields[MAXFIELDS];
	const char *kind, *path;
	size_t i;
	int n, encode = 0;

	argv0 = argv[0];
	if (argc == 2 && strcmp(argv[1], "-l") == 0) {
		/* The list a harness author needs before writing anything.
		 * It is the table below and not a second copy of it. */
		for (i = 0; i < sizeof kinds / sizeof kinds[0]; i++)
			printf("%s\n", kinds[i].name);
		return 0;
	} else if (argc == 4 && strcmp(argv[1], "-e") == 0) {
		encode = 1;
		kind = argv[2];
		path = argv[3];
	} else if (argc == 3) {
		kind = argv[1];
		path = argv[2];
	} else {
		fprintf(stderr, "usage: %s kind rawfile\n", argv0);
		fprintf(stderr, "       %s -e kind expectfile\n", argv0);
		fprintf(stderr, "       %s -l\n", argv0);
		return 2;
	}

	for (i = 0; i < sizeof kinds / sizeof kinds[0]; i++) {
		if (strcmp(kinds[i].name, kind) != 0)
			continue;
		if (!encode) {
			n = readraw(path, blobs, MAXBLOBS);
			if (n != kinds[i].blobs)
				fatal("%s: expected %d blob%s, got %d", kind,
				      kinds[i].blobs,
				      kinds[i].blobs == 1 ? "" : "s", n);
			kinds[i].decode(blobs);
		} else if (kinds[i].encode == NULL && kinds[i].layout == NULL) {
			fatal("kind %s is not of the encode class", kind);
		} else {
			n = readexpect(path, fields, MAXFIELDS);
			if (kinds[i].encode != NULL)
				kinds[i].encode(fields, n);
			else
				encode_layout(kinds[i].layout, fields, n);
		}
		return 0;
	}

	fatal("unknown kind %s", kind);
	return 1;
}
