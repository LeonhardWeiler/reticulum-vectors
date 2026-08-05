// Conformance harness for attermann/microReticulum.
//
//	micro kind rawfile
//
// See ../README for what a harness may and may not do.

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

#include "Identity.h"
#include "Destination.h"
#include "Packet.h"
#include "Bytes.h"
#include "Type.h"
#include "Cryptography/HKDF.h"
#include "Cryptography/Token.h"
#include "Cryptography/X25519.h"
#include "Link.h"

static const int W = 18;
static std::vector<std::string> out;

static void f(const char *name, const std::string &value) {
	char buf[64];
	snprintf(buf, sizeof buf, "%-*s ", W, name);
	out.push_back(std::string(buf) + value);
}

static std::string hexs(const RNS::Bytes &b) { return b.toHex(); }

static std::vector<RNS::Bytes> read_raw(const char *path, std::vector<bool> &absent) {
	std::ifstream in(path);
	std::string line;
	std::vector<RNS::Bytes> blobs;
	while (std::getline(in, line)) {
		while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
		if (line.empty()) continue;
		if (line == "-") { blobs.push_back(RNS::Bytes()); absent.push_back(true); continue; }
		RNS::Bytes b;
		b.assignHex(line.c_str());
		blobs.push_back(b);
		absent.push_back(false);
	}
	return blobs;
}

static void kind_identity(std::vector<RNS::Bytes> &b) {
	RNS::Identity id({RNS::Type::NONE});
	id = RNS::Identity(false);
	id.load_public_key(b[0]);
	RNS::Bytes pub = id.get_public_key();
	f("public_key", hexs(pub));
	f("x25519_public", hexs(pub.left(32)));
	f("ed25519_public", hexs(pub.mid(32)));
	f("identity_hash", hexs(id.hash()));
}

static void kind_keyset(std::vector<RNS::Bytes> &b) {
	RNS::Identity id(false);
	id.load_private_key(b[0]);
	RNS::Bytes prv = id.get_private_key();
	RNS::Bytes pub = id.get_public_key();
	f("private_key", hexs(prv));
	f("x25519_private", hexs(prv.left(32)));
	f("ed25519_private", hexs(prv.mid(32)));
	f("public_key", hexs(pub));
	f("x25519_public", hexs(pub.left(32)));
	f("ed25519_public", hexs(pub.mid(32)));
	f("identity_hash", hexs(id.hash()));
}

static void kind_destination(std::vector<RNS::Bytes> &b, bool no_identity) {
	std::string name((const char *)b[0].data(), b[0].size());
	size_t dot = name.find('.');
	std::string app = name.substr(0, dot);
	std::string aspects = (dot == std::string::npos) ? "" : name.substr(dot + 1);

	RNS::Bytes nh = RNS::Destination::name_hash(app.c_str(),
	                                            (dot == std::string::npos) ? "" : aspects.c_str());

	f("name", hexs(b[0]));
	f("app_name", hexs(RNS::Bytes((const uint8_t *)app.data(), app.size())));
	if (dot != std::string::npos) {
		size_t start = dot + 1;
		while (true) {
			size_t next = name.find('.', start);
			{
				std::string a = name.substr(start, next == std::string::npos ? std::string::npos : next - start);
				f("aspect", hexs(RNS::Bytes((const uint8_t *)a.data(), a.size())));
			}
			if (next == std::string::npos) break;
			start = next + 1;
		}
	}
	f("name_hash", hexs(nh));

	RNS::Bytes material = nh;
	if (no_identity) {
		f("identity_hash", "-");
	} else {
		f("identity_hash", hexs(b[1]));
		material << b[1];
	}
	f("destination_hash", hexs(RNS::Identity::truncated_hash(material)));
}

static void kind_signature(std::vector<RNS::Bytes> &b) {
	RNS::Identity id(false);
	id.load_public_key(b[0]);
	f("ed25519_public", hexs(b[0].mid(32)));
	char lenbuf[32];
	snprintf(lenbuf, sizeof lenbuf, "%zu", (size_t)b[1].size());
	f("message_length", lenbuf);
	f("message_sha256", hexs(RNS::Identity::full_hash(b[1])));
	f("signature", hexs(b[2]));
	f("valid", id.validate(b[2], b[1]) ? "yes" : "no");
}

static void invalid(const char *reason, const char *k1, size_t v1, const char *k2, size_t v2) {
	char buf[32];
	f("invalid", reason);
	snprintf(buf, sizeof buf, "%zu", v1); f(k1, buf);
	snprintf(buf, sizeof buf, "%zu", v2); f(k2, buf);
}

static const char *dest_types[] = {"single", "group", "plain", "link"};
static const char *packet_types[] = {"data", "announce", "linkrequest", "proof"};
static const char *xport_types[] = {"broadcast", "transport", "relay", "tunnel"};

// Named from microReticulum's own context constants at Type.h:428-437.
static std::string context_name(unsigned c) {
	static char buf[8];
	switch (c) {
	case RNS::Type::Packet::CONTEXT_NONE:   return "none";
	case RNS::Type::Packet::PATH_RESPONSE:  return "path_response";
	case RNS::Type::Packet::KEEPALIVE:      return "keepalive";
	case RNS::Type::Packet::LINKIDENTIFY:   return "link_identify";
	case RNS::Type::Packet::LINKCLOSE:      return "link_close";
	case RNS::Type::Packet::LINKPROOF:      return "link_proof";
	case RNS::Type::Packet::LRRTT:          return "link_rtt";
	case RNS::Type::Packet::LRPROOF:        return "link_request_proof";
	}
	snprintf(buf, sizeof buf, "%02x", c);
	return std::string(buf);
}

static void kind_announce(std::vector<RNS::Bytes> &b) {
	const RNS::Bytes &raw = b[0];
	if (raw.size() < 2) { invalid("short-header", "length", raw.size(), "minimum_length", 2); return; }

	RNS::Packet p(raw);
	if (!p.unpack()) { invalid("short-header", "length", raw.size(), "minimum_length", 19); return; }

	unsigned flags = raw.data()[0];
	unsigned hops = raw.data()[1];
	unsigned header_type = (flags & 0x40) >> 6;
	unsigned context_flag = (flags & 0x20) >> 5;
	unsigned transport_type = (flags & 0x10) >> 4;
	unsigned destination_type = (flags & 0x0c) >> 2;
	unsigned packet_type = flags & 0x03;

	RNS::Bytes payload = p.data();
	size_t minimum = 64 + 10 + 10 + 64 + (context_flag ? 32 : 0);
	if (payload.size() < minimum) { invalid("short-payload", "payload_length", payload.size(), "minimum_length", minimum); return; }

	size_t at = 0;
	RNS::Bytes public_key = payload.mid(at, 64); at += 64;
	RNS::Bytes name_hash = payload.mid(at, 10); at += 10;
	RNS::Bytes random_hash = payload.mid(at, 10); at += 10;
	RNS::Bytes ratchet;
	if (context_flag) { ratchet = payload.mid(at, 32); at += 32; }
	RNS::Bytes signature = payload.mid(at, 64); at += 64;
	RNS::Bytes app_data = payload.mid(at);

	RNS::Bytes identity_hash = RNS::Identity::truncated_hash(public_key);
	RNS::Bytes material = name_hash;
	material << identity_hash;
	RNS::Bytes expected = RNS::Identity::truncated_hash(material);

	RNS::Bytes signed_data;
	signed_data << p.destination_hash() << public_key << name_hash << random_hash;
	if (context_flag) signed_data << ratchet;
	signed_data << app_data;

	char buf[32];
	snprintf(buf, sizeof buf, "%02x", flags); f("flags", buf);
	snprintf(buf, sizeof buf, "%u", header_type + 1); f("header_type", buf);
	f("context_flag", context_flag ? "set" : "unset");
	f("transport_type", xport_types[transport_type]);
	f("destination_type", dest_types[destination_type]);
	f("packet_type", packet_types[packet_type]);
	snprintf(buf, sizeof buf, "%u", hops); f("hops", buf);
	if (header_type == 1) f("transport_id", hexs(p.transport_id()));
	else f("transport_id", "-");
	f("destination_hash", hexs(p.destination_hash()));
	f("context", context_name((unsigned)p.context()));
	snprintf(buf, sizeof buf, "%zu", (size_t)payload.size()); f("payload_length", buf);
	f("public_key", hexs(public_key));
	f("name_hash", hexs(name_hash));
	f("random_hash", hexs(random_hash));
	f("ratchet", context_flag ? hexs(ratchet) : "-");
	f("signature", hexs(signature));
	f("app_data", app_data.size() ? hexs(app_data) : "-");
	f("identity_hash", hexs(identity_hash));
	f("expected_hash", hexs(expected));
	f("destination_match", p.destination_hash() == expected ? "yes" : "no");
	f("signed_data", hexs(signed_data));

	// Verdict from the implementation's own validator.
	f("signature_valid", RNS::Identity::validate_announce(p, true) ? "yes" : "no");
}

// microReticulum exposes no entry point that yields the header fields
// on their own, so this mirrors what kind_announce() above already does.
static void print_header(RNS::Packet &p, const RNS::Bytes &raw) {
	char buf[32];
	unsigned flags = raw.data()[0];
	unsigned header_type = (flags & 0x40) >> 6;
	snprintf(buf, sizeof buf, "%02x", flags); f("flags", buf);
	snprintf(buf, sizeof buf, "%u", header_type + 1); f("header_type", buf);
	f("context_flag", ((flags & 0x20) >> 5) ? "set" : "unset");
	f("transport_type", xport_types[(flags & 0x10) >> 4]);
	f("destination_type", dest_types[(flags & 0x0c) >> 2]);
	f("packet_type", packet_types[flags & 0x03]);
	snprintf(buf, sizeof buf, "%u", (unsigned)raw.data()[1]); f("hops", buf);
	if (header_type == 1) f("transport_id", hexs(p.transport_id()));
	else f("transport_id", "-");
	f("destination_hash", hexs(p.destination_hash()));
	f("context", context_name((unsigned)p.context()));
	snprintf(buf, sizeof buf, "%zu", (size_t)p.data().size()); f("payload_length", buf);
}

static void kind_encrypted(std::vector<RNS::Bytes> &b, bool no_ratchet) {
	const RNS::Bytes &priv = b[0];
	const RNS::Bytes &raw = b[2];
	char buf[32];

	// Echoes of the input lines, so that expect holds every byte of raw.
	// Not a claim about microReticulum: the harness was handed these.
	f("recipient_private", hexs(priv));
	f("ratchet_private", no_ratchet ? "-" : hexs(b[1]));

	if (raw.size() < 2) { invalid("short-header", "length", raw.size(), "minimum_length", 2); return; }
	RNS::Packet p(raw);
	if (!p.unpack()) { invalid("short-header", "length", raw.size(), "minimum_length", 19); return; }

	RNS::Bytes payload = p.data();
	if (payload.size() < 32 + 48) {
		invalid("short-payload", "payload_length", payload.size(), "minimum_length", 32 + 48);
		return;
	}

	RNS::Bytes ephemeral = payload.left(32);
	RNS::Bytes token = payload.mid(32);
	RNS::Bytes iv = token.left(16);
	RNS::Bytes ct = token.mid(16, token.size() - 48);
	RNS::Bytes mac = token.mid(token.size() - 32);

	RNS::Identity id(false);
	id.load_private_key(priv);

	RNS::Bytes agree = no_ratchet ? priv.left(32) : b[1];
	RNS::Bytes ratchet_pub;
	if (!no_ratchet)
		ratchet_pub = RNS::Cryptography::X25519PrivateKey::from_private_bytes(b[1])->public_key()->public_bytes();

	RNS::Bytes shared = RNS::Cryptography::X25519PrivateKey::from_private_bytes(agree)->exchange(ephemeral);
	RNS::Bytes derived = RNS::Cryptography::hkdf(RNS::Type::Identity::DERIVED_KEY_LENGTH,
	                                             shared, id.hash(), {RNS::Bytes::NONE});
	size_t half = derived.size() / 2;

	RNS::Cryptography::Token tok(derived);
	bool hmac_ok = tok.verify_hmac(token);

	// microReticulum's decrypt takes no ratchet, so the ratchet vector
	// exercises the identity key path here. The divergence is reported
	// rather than worked around.
	RNS::Bytes plaintext = id.decrypt(payload);

	print_header(p, raw);
	f("ephemeral_public", hexs(ephemeral));
	f("iv", hexs(iv));
	f("ciphertext", hexs(ct));
	f("hmac", hexs(mac));
	f("identity_hash", hexs(id.hash()));
	f("ratchet_public", no_ratchet ? "-" : hexs(ratchet_pub));
	f("shared_key", hexs(shared));
	f("signing_key", hexs(derived.left(half)));
	f("encryption_key", hexs(derived.mid(half)));
	f("hmac_valid", hmac_ok ? "yes" : "no");
	if (!hmac_ok) {
		f("plaintext_length", "-");
		f("plaintext", "-");
	} else {
		snprintf(buf, sizeof buf, "%zu", (size_t)plaintext.size());
		f("plaintext_length", buf);
		f("plaintext", plaintext.size() ? hexs(plaintext) : "-");
	}
}

static const size_t ECPUBSIZE = 64;
static const size_t SIGNALLEN = 3;

static void print_mode(RNS::Type::Link::link_mode mode) {
	char buf[8];
	if (mode == RNS::Type::Link::MODE_AES256_CBC) { f("mode", "aes256_cbc"); return; }
	snprintf(buf, sizeof buf, "%02x", (unsigned)mode);
	f("mode", buf);
}

static void kind_linkrequest(std::vector<RNS::Bytes> &b) {
	const RNS::Bytes &raw = b[0];
	char buf[32];

	if (raw.size() < 2) { invalid("short-header", "length", raw.size(), "minimum_length", 2); return; }
	RNS::Packet p(raw);
	if (!p.unpack()) { invalid("short-header", "length", raw.size(), "minimum_length", 19); return; }

	RNS::Bytes payload = p.data();
	// The rule validate_request applies at Link.cpp:298. It is repeated
	// here because that function wants a destination to own the link.
	bool signalled = payload.size() == ECPUBSIZE + SIGNALLEN;
	if (!signalled && payload.size() != ECPUBSIZE) {
		invalid("invalid-length", "payload_length", payload.size(), "accepted_length", ECPUBSIZE);
		snprintf(buf, sizeof buf, "%zu", ECPUBSIZE + SIGNALLEN);
		f("signalled_length", buf);
		return;
	}

	print_header(p, raw);
	f("x25519_public", hexs(payload.left(32)));
	f("ed25519_public", hexs(payload.mid(32, 32)));
	f("signalling", signalled ? hexs(payload.mid(ECPUBSIZE)) : "-");
	print_mode(RNS::Link::mode_from_lr_packet(p));
	if (signalled) {
		snprintf(buf, sizeof buf, "%u", (unsigned)RNS::Link::mtu_from_lr_packet(p));
		f("mtu", buf);
	} else {
		f("mtu", "-");
	}
	f("link_id", hexs(RNS::Link::link_id_from_lr_packet(p)));
}

static void kind_linkproof(std::vector<RNS::Bytes> &b) {
	const RNS::Bytes &request_raw = b[0];
	const RNS::Bytes &identity_public = b[1];
	const RNS::Bytes &raw = b[2];
	char buf[32];

	f("link_request", hexs(request_raw));
	f("signer_public", hexs(identity_public));

	if (raw.size() < 2) { invalid("short-header", "length", raw.size(), "minimum_length", 2); return; }
	RNS::Packet p(raw);
	if (!p.unpack()) { invalid("short-header", "length", raw.size(), "minimum_length", 19); return; }

	RNS::Bytes payload = p.data();
	bool signalled = payload.size() == 96 + SIGNALLEN;
	if (!signalled && payload.size() != 96) {
		invalid("invalid-length", "payload_length", payload.size(), "accepted_length", 96);
		snprintf(buf, sizeof buf, "%zu", (size_t)(96 + SIGNALLEN));
		f("signalled_length", buf);
		return;
	}

	RNS::Packet request(request_raw);
	request.unpack();
	RNS::Bytes link_id = RNS::Link::link_id_from_lr_packet(request);

	RNS::Bytes signature = payload.left(64);
	RNS::Bytes x25519_public = payload.mid(64, 32);
	RNS::Bytes signalling = signalled ? payload.mid(96) : RNS::Bytes();
	RNS::Bytes signer_ed = identity_public.mid(32);

	// validate_proof drives a link state machine and returns nothing, so
	// the material is assembled here and verified with microReticulum's
	// own Identity::validate.
	RNS::Bytes signed_data;
	signed_data << link_id << x25519_public << signer_ed << signalling;

	RNS::Identity signer(false);
	signer.load_public_key(identity_public);

	print_header(p, raw);
	f("link_id", hexs(link_id));
	f("link_id_match", p.destination_hash() == link_id ? "yes" : "no");
	f("signature", hexs(signature));
	f("x25519_public", hexs(x25519_public));
	f("signalling", signalled ? hexs(signalling) : "-");
	print_mode(RNS::Link::mode_from_lp_packet(p));
	if (signalled) {
		snprintf(buf, sizeof buf, "%u", (unsigned)RNS::Link::mtu_from_lp_packet(p));
		f("mtu", buf);
	} else {
		f("mtu", "-");
	}
	f("signer_ed25519", hexs(signer_ed));
	f("signed_data", hexs(signed_data));
	f("signature_valid", signer.validate(signature, signed_data) ? "yes" : "no");
}

static void kind_linkdata(std::vector<RNS::Bytes> &b) {
	const RNS::Bytes &request_raw = b[0];
	const RNS::Bytes &responder_private = b[1];
	const RNS::Bytes &raw = b[2];
	char buf[32];

	f("link_request", hexs(request_raw));
	f("responder_private", hexs(responder_private));

	if (raw.size() < 2) { invalid("short-header", "length", raw.size(), "minimum_length", 2); return; }
	RNS::Packet p(raw);
	if (!p.unpack()) { invalid("short-header", "length", raw.size(), "minimum_length", 19); return; }

	RNS::Packet request(request_raw);
	request.unpack();
	RNS::Bytes link_id = RNS::Link::link_id_from_lr_packet(request);
	RNS::Bytes payload = p.data();

	print_header(p, raw);
	f("link_id", hexs(link_id));
	f("link_id_match", p.destination_hash() == link_id ? "yes" : "no");

	if ((unsigned)p.context() == RNS::Type::Packet::KEEPALIVE) {
		f("encrypted", "no");
		snprintf(buf, sizeof buf, "%zu", (size_t)payload.size());
		f("plaintext_length", buf);
		f("plaintext", payload.size() ? hexs(payload) : "-");
		return;
	}
	f("encrypted", "yes");

	RNS::Bytes iv = payload.left(16);
	RNS::Bytes ct = payload.mid(16, payload.size() - 48);
	RNS::Bytes mac = payload.mid(payload.size() - 32);

	RNS::Bytes shared = RNS::Cryptography::X25519PrivateKey::from_private_bytes(responder_private)
	                        ->exchange(request.data().left(32));
	RNS::Bytes derived = RNS::Cryptography::hkdf(64, shared, link_id, {RNS::Bytes::NONE});
	size_t half = derived.size() / 2;

	RNS::Cryptography::Token tok(derived);
	bool hmac_ok = tok.verify_hmac(payload);
	RNS::Bytes plaintext = hmac_ok ? tok.decrypt(payload) : RNS::Bytes();

	f("iv", hexs(iv));
	f("ciphertext", hexs(ct));
	f("hmac", hexs(mac));
	f("shared_key", hexs(shared));
	f("signing_key", hexs(derived.left(half)));
	f("encryption_key", hexs(derived.mid(half)));
	f("hmac_valid", hmac_ok ? "yes" : "no");
	if (!hmac_ok) {
		f("plaintext_length", "-");
		f("plaintext", "-");
		return;
	}
	snprintf(buf, sizeof buf, "%zu", (size_t)plaintext.size());
	f("plaintext_length", buf);
	f("plaintext", plaintext.size() ? hexs(plaintext) : "-");

	if ((unsigned)p.context() == RNS::Type::Packet::LINKIDENTIFY && plaintext.size() == 128) {
		RNS::Bytes pub = plaintext.left(64);
		RNS::Bytes sig = plaintext.mid(64);
		RNS::Bytes signed_data;
		signed_data << link_id << pub;

		RNS::Identity id(false);
		id.load_public_key(pub);

		f("identity_public", hexs(pub));
		f("identity_hash", hexs(id.hash()));
		f("identity_signed", hexs(signed_data));
		f("identity_valid", id.validate(sig, signed_data) ? "yes" : "no");
	}
}

int main(int argc, char **argv) {
	if (argc != 3) { fprintf(stderr, "usage: micro kind rawfile\n"); return 2; }

	std::vector<bool> absent;
	std::vector<RNS::Bytes> blobs = read_raw(argv[2], absent);
	std::string kind(argv[1]);

	try {
		if (kind == "identity") kind_identity(blobs);
		else if (kind == "keyset") kind_keyset(blobs);
		else if (kind == "destination") kind_destination(blobs, absent[1]);
		else if (kind == "signature") kind_signature(blobs);
		else if (kind == "announce") kind_announce(blobs);
		else if (kind == "encrypted") kind_encrypted(blobs, absent[1]);
		else if (kind == "linkrequest") kind_linkrequest(blobs);
		else if (kind == "linkproof") kind_linkproof(blobs);
		else if (kind == "linkdata") kind_linkdata(blobs);
		else { fprintf(stderr, "unknown kind %s\n", argv[1]); return 2; }
	} catch (const std::exception &e) {
		out.clear();
		f("error", e.what());
	}

	for (size_t i = 0; i < out.size(); i++) printf("%s\n", out[i].c_str());
	return 0;
}
