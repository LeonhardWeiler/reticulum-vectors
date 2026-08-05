// Conformance harness for liamcottle/rns.js.
//
// Prints the reticulum-vectors expect format using only rns.js's own
// types and derivations. Where rns.js has no entry point that returns
// the intermediate values, its logic is followed step by step using its
// own primitives; those places are marked.
//
//	node dump.js kind rawfile

import fs from "fs";
// Imported by file path: the harness lives outside rns.js's package.
import { x25519 } from "../src/rns.js/node_modules/@noble/curves/esm/ed25519.js";
import Fernet from "../src/rns.js/src/fernet.js";
import Identity from "../src/rns.js/src/identity.js";
import Destination from "../src/rns.js/src/destination.js";
import Packet from "../src/rns.js/src/packet.js";
import Cryptography from "../src/rns.js/src/cryptography.js";
import Constants from "../src/rns.js/src/constants.js";

const W = 18;
const out = [];
const f = (name, value) => out.push(name.padEnd(W) + " " + value);
const hex = (b) => Buffer.from(b).toString("hex");

function readRaw(path) {
    return fs.readFileSync(path, "utf8")
        .split("\n")
        .filter((l) => l.length > 0)
        .map((l) => (l === "-" ? null : Buffer.from(l, "hex")));
}

function identity(blobs) {
    const id = Identity.fromPublicKey(blobs[0]);
    f("public_key", hex(id.getPublicKey()));
    f("x25519_public", hex(id.publicKeyBytes));
    f("ed25519_public", hex(id.signaturePublicKeyBytes));
    f("identity_hash", hex(id.hash));
}

function keyset(blobs) {
    const id = Identity.fromPrivateKey(blobs[0]);
    f("private_key", hex(id.getPrivateKey()));
    f("x25519_private", hex(id.privateKeyBytes));
    f("ed25519_private", hex(id.signaturePrivateKeyBytes));
    f("public_key", hex(id.getPublicKey()));
    f("x25519_public", hex(id.publicKeyBytes));
    f("ed25519_public", hex(id.signaturePublicKeyBytes));
    f("identity_hash", hex(id.hash));
}

function destination(blobs) {
    const name = blobs[0].toString("utf8");
    const nameBytes = blobs[0];
    const [appName, ...aspects] = name.split(".");

    // Destination.hash takes an Identity, but the vector supplies only
    // an identity hash. rns.js concatenates identity.hash, so a stub
    // carrying just that field exercises the same code path.
    const idStub = blobs[1] === null ? null : { hash: blobs[1] };

    f("name", hex(blobs[0]));
    f("app_name", hex(Buffer.from(appName, "utf8")));
    for (const a of aspects) f("aspect", hex(Buffer.from(a, "utf8")));
    f("name_hash", hex(Cryptography.fullHash(Destination.expandName(null, appName, ...aspects))
        .slice(0, Identity.NAME_HASH_LENGTH_IN_BYTES)));
    f("identity_hash", blobs[1] === null ? "-" : hex(blobs[1]));
    f("destination_hash", hex(Destination.hash(idStub, appName, ...aspects)));
}

function signature(blobs) {
    const id = Identity.fromPublicKey(blobs[0]);
    f("ed25519_public", hex(id.signaturePublicKeyBytes));
    f("message_length", String(blobs[1].length));
    f("message_sha256", hex(Cryptography.sha256(blobs[1])));
    f("signature", hex(blobs[2]));
    f("valid", id.validate(blobs[2], blobs[1]) ? "yes" : "no");
}

const DEST_TYPES = ["single", "group", "plain", "link"];
const PACKET_TYPES = ["data", "announce", "linkrequest", "proof"];
const XPORT_TYPES = ["broadcast", "transport", "relay", "tunnel"];

function announce(blobs) {
    const raw = blobs[0];
    const invalid = (reason, ...pairs) => {
        f("invalid", reason);
        for (const [k, v] of pairs) f(k, String(v));
    };

    if (raw.length < 2) return invalid("short-header", ["length", raw.length], ["minimum_length", 2]);

    const p = Packet.fromBytes(raw);
    if (p === null || p === undefined) return invalid("short-header", ["length", raw.length], ["minimum_length", 19]);

    // No hop limit check here: rns.js has none, and adding one would
    // hide that. The vector at the limit is expected to fail.

    const payload = p.data;
    const min = Identity.KEYSIZE_IN_BYTES + Identity.NAME_HASH_LENGTH_IN_BYTES + 10
        + Identity.SIGLENGTH_IN_BYTES
        + (p.contextFlag === Packet.FLAG_SET ? Identity.RATCHETSIZE_IN_BYTES : 0);
    if (payload.length < min) return invalid("short-payload", ["payload_length", payload.length], ["minimum_length", min]);

    // Follows src/announce.js:26-49 with rns.js's own constants.
    const data = Array.from(payload);
    const publicKey = Buffer.from(data.splice(0, Identity.KEYSIZE_IN_BYTES));
    const nameHash = Buffer.from(data.splice(0, Identity.NAME_HASH_LENGTH_IN_BYTES));
    const randomHash = Buffer.from(data.splice(0, 10));
    let ratchet = Buffer.from([]);
    if (p.contextFlag === Packet.FLAG_SET) {
        ratchet = Buffer.from(data.splice(0, Identity.RATCHETSIZE_IN_BYTES));
    }
    const sig = Buffer.from(data.splice(0, Identity.SIGLENGTH_IN_BYTES));
    const appData = Buffer.from(data);

    const signedData = Buffer.concat([p.destinationHash, publicKey, nameHash, randomHash, ratchet, appData]);
    const announced = Identity.fromPublicKey(publicKey);
    const expected = Cryptography.fullHash(Buffer.concat([nameHash, announced.hash]))
        .slice(0, Constants.TRUNCATED_HASHLENGTH_IN_BYTES);

    f("flags", raw[0].toString(16).padStart(2, "0"));
    f("header_type", String(p.headerType + 1));
    f("context_flag", p.contextFlag === Packet.FLAG_SET ? "set" : "unset");
    f("transport_type", XPORT_TYPES[p.transportType]);
    f("destination_type", DEST_TYPES[p.destinationType]);
    f("packet_type", PACKET_TYPES[p.packetType]);
    f("hops", String(p.hops));
    f("transport_id", p.headerType === Packet.HEADER_2 ? hex(p.transportId) : "-");
    f("destination_hash", hex(p.destinationHash));
    f("context", p.context === 0 ? "none" : p.context === 0x0b ? "path_response"
        : p.context.toString(16).padStart(2, "0"));
    f("payload_length", String(payload.length));
    f("public_key", hex(publicKey));
    f("name_hash", hex(nameHash));
    f("random_hash", hex(randomHash));
    f("ratchet", ratchet.length ? hex(ratchet) : "-");
    f("signature", hex(sig));
    f("app_data", appData.length ? hex(appData) : "-");
    f("identity_hash", hex(announced.hash));
    f("expected_hash", hex(expected));
    f("destination_match", p.destinationHash.equals(expected) ? "yes" : "no");
    f("signed_data", hex(signedData));
    f("signature_valid", announced.validate(sig, signedData) ? "yes" : "no");
}

// rns.js exposes no entry point that yields the header fields on their
// own, so this mirrors what announce() above already does.
function header(p, raw) {
    f("flags", raw[0].toString(16).padStart(2, "0"));
    f("header_type", String(p.headerType + 1));
    f("context_flag", p.contextFlag === Packet.FLAG_SET ? "set" : "unset");
    f("transport_type", XPORT_TYPES[p.transportType]);
    f("destination_type", DEST_TYPES[p.destinationType]);
    f("packet_type", PACKET_TYPES[p.packetType]);
    f("hops", String(p.hops));
    f("transport_id", p.headerType === Packet.HEADER_2 ? hex(p.transportId) : "-");
    f("destination_hash", hex(p.destinationHash));
    f("context", p.context === 0 ? "none" : p.context === 0x0b ? "path_response"
        : p.context.toString(16).padStart(2, "0"));
    f("payload_length", String(p.data.length));
}

function encrypted(blobs) {
    const priv = blobs[0], ratchetPriv = blobs[1], raw = blobs[2];
    const invalid = (reason, ...pairs) => {
        f("invalid", reason);
        for (const [k, v] of pairs) f(k, String(v));
    };

    if (raw.length < 2) return invalid("short-header", ["length", raw.length], ["minimum_length", 2]);
    const p = Packet.fromBytes(raw);
    if (p === null || p === undefined) return invalid("short-header", ["length", raw.length], ["minimum_length", 19]);

    const payload = p.data;
    const min = Identity.KEYSIZE_IN_BYTES / 2 + Fernet.FERNET_OVERHEAD;
    if (payload.length < min) return invalid("short-payload", ["payload_length", payload.length], ["minimum_length", min]);

    const ephemeral = payload.slice(0, Identity.KEYSIZE_IN_BYTES / 2);
    const token = payload.slice(Identity.KEYSIZE_IN_BYTES / 2);
    const iv = token.slice(0, 16);
    const ct = token.slice(16, -32);
    const mac = token.slice(-32);

    const id = Identity.fromPrivateKey(priv);

    // rns.js has no ratchet path in decrypt(); the agreement is done
    // with its own primitive so the rest can still be compared.
    const agree = ratchetPriv === null ? id.privateKeyBytes : ratchetPriv;
    const shared = Buffer.from(x25519.getSharedSecret(agree, ephemeral));

    // Follows src/identity.js:237. The derived length is rns.js's own.
    const derived = Cryptography.hkdf(32, shared, id.hash);
    const half = derived.length / 2;
    const signing = derived.slice(0, half);
    const encryption = derived.slice(half);

    const hmacOk = Cryptography.hmacSha256(signing, Buffer.concat([iv, ct])).equals(mac);

    let plaintext = null;
    try {
        plaintext = new Fernet(derived).decrypt(token);
    } catch (e) {
        plaintext = null;
    }

    header(p, raw);
    f("ephemeral_public", hex(ephemeral));
    f("iv", hex(iv));
    f("ciphertext", hex(ct));
    f("hmac", hex(mac));
    f("identity_hash", hex(id.hash));
    f("ratchet_public", ratchetPriv === null ? "-" : hex(Buffer.from(x25519.getPublicKey(ratchetPriv))));
    f("shared_key", hex(shared));
    f("signing_key", hex(signing));
    f("encryption_key", hex(encryption));
    f("hmac_valid", hmacOk ? "yes" : "no");
    f("plaintext_length", plaintext === null ? "-" : String(plaintext.length));
    f("plaintext", plaintext === null || plaintext.length === 0 ? "-" : hex(plaintext));
}

const [kind, path] = process.argv.slice(2);
const blobs = readRaw(path);
const kinds = { identity, keyset, destination, signature, announce, encrypted };
if (!(kind in kinds)) {
    console.error("unknown kind " + kind);
    process.exit(2);
}
try {
    kinds[kind](blobs);
} catch (e) {
    out.length = 0;
    f("error", String(e.message ?? e).split("\n")[0]);
}
process.stdout.write(out.join("\n") + "\n");
