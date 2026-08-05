// Conformance harness for attermann/microReticulum.
//
//	micro kind rawfile

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
	unsigned context = (unsigned)p.context();
	if (context == 0x00) f("context", "none");
	else if (context == 0x0b) f("context", "path_response");
	else { snprintf(buf, sizeof buf, "%02x", context); f("context", buf); }
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
		else { fprintf(stderr, "unknown kind %s\n", argv[1]); return 2; }
	} catch (const std::exception &e) {
		out.clear();
		f("error", e.what());
	}

	for (size_t i = 0; i < out.size(); i++) printf("%s\n", out[i].c_str());
	return 0;
}
