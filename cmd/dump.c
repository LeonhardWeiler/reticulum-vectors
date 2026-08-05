/* dump - decode one Reticulum object and print its fields.
 *
 *	dump kind rawfile
 *
 * The output format is the format used by the expect file of every
 * vector, so that checking is a diff. See ../README.
 *
 * dump is a second implementation of the wire format, independent of
 * python-rns. That is its purpose. It deliberately shares no code with
 * the generator. */

#include "sha256.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXBLOB   8192
#define MAXBLOBS  8
#define FIELDW    18

#define IDENTITY_KEY_HALF   32
#define IDENTITY_HASH_LEN   16
#define NAME_HASH_LEN       10

struct blob {
	uint8_t  data[MAXBLOB];
	size_t   len;
	int      absent;	/* the line was "-" */
};

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

	printf("%-*s ", FIELDW, name);
	for (i = 0; i < n; i++)
		printf("%02x", p[i]);
	putchar('\n');
}

static void field_bytes(const char *name, const uint8_t *p, size_t n)
{
	printf("%-*s ", FIELDW, name);
	fwrite(p, 1, n, stdout);
	putchar('\n');
}

static int unhex(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* Read a raw file: one hex blob per line, or "-" for an absent blob. */
static int readraw(const char *path, struct blob *out, int max)
{
	FILE *f;
	char line[MAXBLOB*2 + 4];
	int n = 0;

	if ((f = fopen(path, "r")) == NULL)
		fatal("cannot open %s", path);

	while (fgets(line, sizeof line, f) != NULL) {
		size_t len = strlen(line), i;
		struct blob *b;

		while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
			line[--len] = '\0';
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
		if (len % 2 != 0)
			fatal("%s: odd hex length on line %d", path, n);
		if (len / 2 > MAXBLOB)
			fatal("%s: line %d exceeds %d bytes", path, n, MAXBLOB);

		for (i = 0; i < len; i += 2) {
			int hi = unhex(line[i]), lo = unhex(line[i+1]);
			if (hi < 0 || lo < 0)
				fatal("%s: bad hex on line %d", path, n);
			b->data[b->len++] = (uint8_t)(hi << 4 | lo);
		}
	}

	fclose(f);
	return n;
}

static void truncated_hash(const uint8_t *p, size_t n, uint8_t *out, size_t take)
{
	uint8_t full[32];

	sha256(p, n, full);
	memcpy(out, full, take);
}

/* identity: one blob, the 64-byte public key. See ../doc/identity. */
static void dump_identity(struct blob *b, int nblobs)
{
	uint8_t hash[IDENTITY_HASH_LEN];

	if (nblobs != 1)
		fatal("identity: expected 1 blob, got %d", nblobs);
	if (b[0].len != IDENTITY_KEY_HALF*2)
		fatal("identity: public key is %zu bytes, expected %d",
		      b[0].len, IDENTITY_KEY_HALF*2);

	truncated_hash(b[0].data, b[0].len, hash, IDENTITY_HASH_LEN);

	field_hex("public_key",     b[0].data, IDENTITY_KEY_HALF*2);
	field_hex("x25519_public",  b[0].data, IDENTITY_KEY_HALF);
	field_hex("ed25519_public", b[0].data + IDENTITY_KEY_HALF, IDENTITY_KEY_HALF);
	field_hex("identity_hash",  hash, IDENTITY_HASH_LEN);
}

/* destination: two blobs, the utf-8 name and the identity hash.
 * See ../doc/destination. */
static void dump_destination(struct blob *b, int nblobs)
{
	uint8_t name_hash[NAME_HASH_LEN];
	uint8_t material[NAME_HASH_LEN + IDENTITY_HASH_LEN];
	uint8_t dest_hash[IDENTITY_HASH_LEN];
	size_t  matlen, start, i;

	if (nblobs != 2)
		fatal("destination: expected 2 blobs, got %d", nblobs);
	if (!b[1].absent && b[1].len != IDENTITY_HASH_LEN)
		fatal("destination: identity hash is %zu bytes, expected %d",
		      b[1].len, IDENTITY_HASH_LEN);

	truncated_hash(b[0].data, b[0].len, name_hash, NAME_HASH_LEN);

	memcpy(material, name_hash, NAME_HASH_LEN);
	matlen = NAME_HASH_LEN;
	if (!b[1].absent) {
		memcpy(material + matlen, b[1].data, IDENTITY_HASH_LEN);
		matlen += IDENTITY_HASH_LEN;
	}
	truncated_hash(material, matlen, dest_hash, IDENTITY_HASH_LEN);

	field_bytes("name", b[0].data, b[0].len);

	/* Split on dots. The first component is the app name, the rest
	 * are aspects. No component may contain a dot, so a plain scan
	 * is exact. */
	start = 0;
	for (i = 0; i <= b[0].len; i++) {
		if (i == b[0].len || b[0].data[i] == '.') {
			field_bytes(start == 0 ? "app_name" : "aspect",
			            b[0].data + start, i - start);
			start = i + 1;
		}
	}

	field_hex("name_hash", name_hash, NAME_HASH_LEN);
	if (b[1].absent)
		field("identity_hash", "-");
	else
		field_hex("identity_hash", b[1].data, IDENTITY_HASH_LEN);
	field_hex("destination_hash", dest_hash, IDENTITY_HASH_LEN);
}

/* announce: one blob, the whole packet. See ../doc/packet and
 * ../doc/announce. */

#define ADDRLEN      16
#define KEYSIZE      64
#define NAMEHASHLEN  10
#define RANDHASHLEN  10
#define SIGLEN       64
#define RATCHETLEN   32
#define MAX_HOPS     128	/* RNS.Transport.PATHFINDER_M */

static const char *dest_types[]   = { "single", "group", "plain", "link" };
static const char *packet_types[] = { "data", "announce", "linkrequest", "proof" };
static const char *xport_types[]  = { "broadcast", "transport", "relay", "tunnel" };

static void dump_announce(struct blob *b, int nblobs)
{
	const uint8_t *raw, *transport_id, *dest_hash, *payload;
	const uint8_t *public_key, *name_hash, *random_hash, *ratchet, *signature, *app_data;
	uint8_t identity_hash[ADDRLEN], expected_hash[ADDRLEN];
	uint8_t material[NAMEHASHLEN + ADDRLEN];
	uint8_t signed_data[MAXBLOB];
	size_t  len, paylen, applen, at, sdlen, minimum;
	unsigned flags, hops, header_type, context_flag, transport_type;
	unsigned destination_type, packet_type, context;

	if (nblobs != 1)
		fatal("announce: expected 1 blob, got %d", nblobs);

	raw = b[0].data;
	len = b[0].len;

	if (len < 2) {
		field("invalid", "length");
		return;
	}

	flags = raw[0];
	hops  = raw[1];

	header_type      = (flags & 0x40) >> 6;
	context_flag     = (flags & 0x20) >> 5;
	transport_type   = (flags & 0x10) >> 4;
	destination_type = (flags & 0x0c) >> 2;
	packet_type      = (flags & 0x03);

	if (hops >= MAX_HOPS) {
		field("invalid", "hops");
		return;
	}

	if (header_type == 1) {
		if (len < 2 + 2*ADDRLEN + 1) {
			field("invalid", "length");
			return;
		}
		transport_id = raw + 2;
		dest_hash    = raw + 2 + ADDRLEN;
		context      = raw[2 + 2*ADDRLEN];
		payload      = raw + 3 + 2*ADDRLEN;
	} else {
		if (len < 2 + ADDRLEN + 1) {
			field("invalid", "length");
			return;
		}
		transport_id = NULL;
		dest_hash    = raw + 2;
		context      = raw[2 + ADDRLEN];
		payload      = raw + 3 + ADDRLEN;
	}
	paylen = len - (size_t)(payload - raw);

	minimum = KEYSIZE + NAMEHASHLEN + RANDHASHLEN + SIGLEN;
	if (context_flag == 1)
		minimum += RATCHETLEN;
	if (paylen < minimum) {
		field("invalid", "length");
		return;
	}

	at = 0;
	public_key  = payload + at; at += KEYSIZE;
	name_hash   = payload + at; at += NAMEHASHLEN;
	random_hash = payload + at; at += RANDHASHLEN;
	if (context_flag == 1) {
		ratchet = payload + at; at += RATCHETLEN;
	} else {
		ratchet = NULL;
	}
	signature = payload + at; at += SIGLEN;
	app_data  = payload + at;
	applen    = paylen - at;

	truncated_hash(public_key, KEYSIZE, identity_hash, ADDRLEN);
	memcpy(material, name_hash, NAMEHASHLEN);
	memcpy(material + NAMEHASHLEN, identity_hash, ADDRLEN);
	truncated_hash(material, sizeof material, expected_hash, ADDRLEN);

	/* app_data is transmitted after the signature but signed before
	 * it. Getting this wrong is the most likely reason for a valid
	 * announce to be rejected. */
	sdlen = 0;
	memcpy(signed_data + sdlen, dest_hash,   ADDRLEN);     sdlen += ADDRLEN;
	memcpy(signed_data + sdlen, public_key,  KEYSIZE);     sdlen += KEYSIZE;
	memcpy(signed_data + sdlen, name_hash,   NAMEHASHLEN); sdlen += NAMEHASHLEN;
	memcpy(signed_data + sdlen, random_hash, RANDHASHLEN); sdlen += RANDHASHLEN;
	if (ratchet != NULL) {
		memcpy(signed_data + sdlen, ratchet, RATCHETLEN);
		sdlen += RATCHETLEN;
	}
	memcpy(signed_data + sdlen, app_data, applen);
	sdlen += applen;

	field("flags", "%02x", flags);
	field("header_type", "%u", header_type + 1);
	field("context_flag", "%s", context_flag ? "set" : "unset");
	field("transport_type", "%s", xport_types[transport_type]);
	field("destination_type", "%s", dest_types[destination_type]);
	field("packet_type", "%s", packet_types[packet_type]);
	field("hops", "%u", hops);
	if (transport_id != NULL)
		field_hex("transport_id", transport_id, ADDRLEN);
	else
		field("transport_id", "-");
	field_hex("destination_hash", dest_hash, ADDRLEN);
	if (context == 0x00)
		field("context", "none");
	else if (context == 0x0b)
		field("context", "path_response");
	else
		field("context", "%02x", context);
	field("payload_length", "%zu", paylen);
	field_hex("public_key", public_key, KEYSIZE);
	field_hex("name_hash", name_hash, NAMEHASHLEN);
	field_hex("random_hash", random_hash, RANDHASHLEN);
	if (ratchet != NULL)
		field_hex("ratchet", ratchet, RATCHETLEN);
	else
		field("ratchet", "-");
	field_hex("signature", signature, SIGLEN);
	if (applen > 0)
		field_hex("app_data", app_data, applen);
	else
		field("app_data", "-");
	field_hex("identity_hash", identity_hash, ADDRLEN);
	field_hex("expected_hash", expected_hash, ADDRLEN);
	field("destination_match", "%s",
	      memcmp(dest_hash, expected_hash, ADDRLEN) == 0 ? "yes" : "no");
	field_hex("signed_data", signed_data, sdlen);
}

int main(int argc, char **argv)
{
	struct blob blobs[MAXBLOBS];
	int n;

	argv0 = argv[0];
	if (argc != 3) {
		fprintf(stderr, "usage: %s kind rawfile\n", argv0);
		return 2;
	}

	n = readraw(argv[2], blobs, MAXBLOBS);

	if (strcmp(argv[1], "identity") == 0)
		dump_identity(blobs, n);
	else if (strcmp(argv[1], "destination") == 0)
		dump_destination(blobs, n);
	else if (strcmp(argv[1], "announce") == 0)
		dump_announce(blobs, n);
	else
		fatal("unknown kind %s", argv[1]);

	return 0;
}
