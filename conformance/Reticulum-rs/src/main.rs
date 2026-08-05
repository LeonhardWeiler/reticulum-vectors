// Conformance harness for BeechatNetworkSystemsLtd/Reticulum-rs.
//
//	rsret kind rawfile
//
// See ../README for what a harness may and may not do.

use std::env;
use std::fs;

use reticulum::destination::{DestinationAnnounce, DestinationName};
use reticulum::hash::AddressHash;
use reticulum::identity::{DecryptIdentity, Identity, PrivateIdentity};
use reticulum::buffer::InputBuffer;
use reticulum::packet::Packet;
use sha2::{Digest, Sha256};

const W: usize = 18;

fn f(out: &mut Vec<String>, name: &str, value: &str) {
    out.push(format!("{:<W$} {}", name, value, W = W));
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn read_raw(path: &str) -> Vec<Option<Vec<u8>>> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let l = l.trim();
            if l == "-" {
                None
            } else {
                Some(
                    (0..l.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&l[i..i + 2], 16).unwrap())
                        .collect(),
                )
            }
        })
        .collect()
}

fn identity(out: &mut Vec<String>, b: &[Option<Vec<u8>>]) {
    let pk = b[0].as_ref().unwrap();
    let id = Identity::new_from_slices(&pk[..32], &pk[32..]);
    f(out, "public_key", &hexs(pk));
    f(out, "x25519_public", &hexs(id.public_key_bytes()));
    f(out, "ed25519_public", &hexs(id.verifying_key_bytes()));
    f(out, "identity_hash", &hexs(id.address_hash.as_slice()));
}

fn keyset(out: &mut Vec<String>, b: &[Option<Vec<u8>>]) {
    let prv = b[0].as_ref().unwrap();
    let id = PrivateIdentity::new_from_hex_string(&hexs(prv)).unwrap();
    let pub_id = id.as_identity();
    let x = pub_id.public_key_bytes();
    let e = pub_id.verifying_key_bytes();
    let mut full = Vec::new();
    full.extend_from_slice(x);
    full.extend_from_slice(e);
    f(out, "private_key", &hexs(prv));
    f(out, "x25519_private", &hexs(&prv[..32]));
    f(out, "ed25519_private", &hexs(&prv[32..]));
    f(out, "public_key", &hexs(&full));
    f(out, "x25519_public", &hexs(x));
    f(out, "ed25519_public", &hexs(e));
    f(out, "identity_hash", &hexs(id.address_hash().as_slice()));
}

fn destination(out: &mut Vec<String>, b: &[Option<Vec<u8>>]) {
    let name = String::from_utf8(b[0].clone().unwrap()).unwrap();
    let mut parts = name.splitn(2, '.');
    let app_name = parts.next().unwrap();
    let aspects = parts.next().unwrap_or("");

    let dn = DestinationName::new(app_name, aspects);

    f(out, "name", &hexs(b[0].as_ref().unwrap()));
    f(out, "app_name", &hexs(app_name.as_bytes()));
    for a in name.split('.').skip(1) {
        f(out, "aspect", &hexs(a.as_bytes()));
    }
    f(out, "name_hash", &hexs(dn.as_name_hash_slice()));
    match &b[1] {
        None => {
            f(out, "identity_hash", "-");
            // EmptyIdentity contributes an empty slice
            // (identity.rs:6), so the hash material is the name hash
            // alone, as in the reference.
            let digest = Sha256::digest(dn.as_name_hash_slice());
            f(out, "destination_hash", &hexs(&digest[..16]));
        }
        Some(ih) => {
            let mut material = Vec::new();
            material.extend_from_slice(dn.as_name_hash_slice());
            material.extend_from_slice(ih);
            let digest = Sha256::digest(&material);
            f(out, "identity_hash", &hexs(ih));
            f(out, "destination_hash", &hexs(&digest[..16]));
        }
    }
}

fn signature(out: &mut Vec<String>, b: &[Option<Vec<u8>>]) {
    let pk = b[0].as_ref().unwrap();
    let msg = b[1].as_ref().unwrap();
    let sig = b[2].as_ref().unwrap();
    let id = Identity::new_from_slices(&pk[..32], &pk[32..]);

    f(out, "ed25519_public", &hexs(&pk[32..]));
    f(out, "message_length", &format!("{}", msg.len()));
    f(out, "message_sha256", &hexs(&Sha256::digest(msg)));
    f(out, "signature", &hexs(sig));

    let ok = match ed25519_dalek::Signature::from_slice(sig) {
        Ok(s) => id.verify(msg, &s).is_ok(),
        Err(_) => false,
    };
    f(out, "valid", if ok { "yes" } else { "no" });
}

fn invalid(out: &mut Vec<String>, reason: &str, pairs: &[(&str, usize)]) {
    f(out, "invalid", reason);
    for (k, v) in pairs {
        f(out, k, &format!("{}", v));
    }
}

const DEST_TYPES: [&str; 4] = ["single", "group", "plain", "link"];
const PACKET_TYPES: [&str; 4] = ["data", "announce", "linkrequest", "proof"];
const XPORT_TYPES: [&str; 4] = ["broadcast", "transport", "relay", "tunnel"];

fn announce(out: &mut Vec<String>, b: &[Option<Vec<u8>>]) {
    let raw = b[0].as_ref().unwrap();
    if raw.len() < 2 {
        return invalid(out, "short-header", &[("length", raw.len()), ("minimum_length", 2)]);
    }

    let flags = raw[0];
    let hops = raw[1];
    let header_type = (flags & 0x40) >> 6;
    let context_flag = (flags & 0x20) >> 5;
    let transport_type = (flags & 0x10) >> 4;
    let destination_type = (flags & 0x0c) >> 2;
    let packet_type = flags & 0x03;

    // Reticulum-rs parses packets through Packet::from_bytes; the call
    // is made so that its acceptance is exercised, but the field
    // decomposition below is taken from the raw bytes because the
    // parsed struct does not expose every field.
    let mut buffer = InputBuffer::new(raw);
    let parsed = Packet::deserialize(&mut buffer);

    let (transport_id, dest_hash, context, payload): (Option<&[u8]>, &[u8], u8, &[u8]) =
        if header_type == 1 {
            if raw.len() < 35 {
                return invalid(out, "short-header", &[("length", raw.len()), ("minimum_length", 35)]);
            }
            (Some(&raw[2..18]), &raw[18..34], raw[34], &raw[35..])
        } else {
            if raw.len() < 19 {
                return invalid(out, "short-header", &[("length", raw.len()), ("minimum_length", 19)]);
            }
            (None, &raw[2..18], raw[18], &raw[19..])
        };

    let mut minimum = 64 + 10 + 10 + 64;
    if context_flag == 1 {
        minimum += 32;
    }
    if payload.len() < minimum {
        return invalid(out, "short-payload",
                       &[("payload_length", payload.len()), ("minimum_length", minimum)]);
    }

    let mut at = 0usize;
    let public_key = &payload[at..at + 64];
    at += 64;
    let name_hash = &payload[at..at + 10];
    at += 10;
    let random_hash = &payload[at..at + 10];
    at += 10;
    let ratchet: Option<&[u8]> = if context_flag == 1 {
        let r = &payload[at..at + 32];
        at += 32;
        Some(r)
    } else {
        None
    };
    let sig = &payload[at..at + 64];
    at += 64;
    let app_data = &payload[at..];

    let id = Identity::new_from_slices(&public_key[..32], &public_key[32..]);

    let mut material = Vec::new();
    material.extend_from_slice(name_hash);
    material.extend_from_slice(id.address_hash.as_slice());
    let expected = Sha256::digest(&material);
    let expected = &expected[..16];

    let mut signed = Vec::new();
    signed.extend_from_slice(dest_hash);
    signed.extend_from_slice(public_key);
    signed.extend_from_slice(name_hash);
    signed.extend_from_slice(random_hash);
    if let Some(r) = ratchet {
        signed.extend_from_slice(r);
    }
    signed.extend_from_slice(app_data);

    f(out, "flags", &format!("{:02x}", flags));
    f(out, "header_type", &format!("{}", header_type + 1));
    f(out, "context_flag", if context_flag == 1 { "set" } else { "unset" });
    f(out, "transport_type", XPORT_TYPES[transport_type as usize]);
    f(out, "destination_type", DEST_TYPES[destination_type as usize]);
    f(out, "packet_type", PACKET_TYPES[packet_type as usize]);
    f(out, "hops", &format!("{}", hops));
    match transport_id {
        Some(t) => f(out, "transport_id", &hexs(t)),
        None => f(out, "transport_id", "-"),
    }
    f(out, "destination_hash", &hexs(dest_hash));
    f(
        out,
        "context",
        match context {
            0x00 => "none".to_string(),
            0x0b => "path_response".to_string(),
            c => format!("{:02x}", c),
        }
        .as_str(),
    );
    f(out, "payload_length", &format!("{}", payload.len()));
    f(out, "public_key", &hexs(public_key));
    f(out, "name_hash", &hexs(name_hash));
    f(out, "random_hash", &hexs(random_hash));
    match ratchet {
        Some(r) => f(out, "ratchet", &hexs(r)),
        None => f(out, "ratchet", "-"),
    }
    f(out, "signature", &hexs(sig));
    if app_data.is_empty() {
        f(out, "app_data", "-");
    } else {
        f(out, "app_data", &hexs(app_data));
    }
    f(out, "identity_hash", &hexs(id.address_hash.as_slice()));
    f(out, "expected_hash", &hexs(expected));
    f(
        out,
        "destination_match",
        if dest_hash == expected { "yes" } else { "no" },
    );
    f(out, "signed_data", &hexs(&signed));

    // The verdict comes from the implementation's own validator, run on
    // the packet it parsed, not from the fields assembled above.
    let verdict = match parsed {
        Ok(p) => DestinationAnnounce::validate(&p).is_ok(),
        Err(_) => false,
    };
    f(out, "signature_valid", if verdict { "yes" } else { "no" });

    let _ = AddressHash::new_from_slice(raw);
}

// Reticulum-rs exposes no entry point that yields the header fields on
// their own, so this mirrors what announce() above already does.
fn print_header(out: &mut Vec<String>, raw: &[u8]) {
    let flags = raw[0];
    let header_type = (flags & 0x40) >> 6;
    let payload_at = 3 + 16 * (header_type as usize + 1);
    f(out, "flags", &format!("{:02x}", flags));
    f(out, "header_type", &format!("{}", header_type + 1));
    f(out, "context_flag", if (flags & 0x20) >> 5 == 1 { "set" } else { "unset" });
    f(out, "transport_type", XPORT_TYPES[((flags & 0x10) >> 4) as usize]);
    f(out, "destination_type", DEST_TYPES[((flags & 0x0c) >> 2) as usize]);
    f(out, "packet_type", PACKET_TYPES[(flags & 0x03) as usize]);
    f(out, "hops", &format!("{}", raw[1]));
    if header_type == 1 {
        f(out, "transport_id", &hexs(&raw[2..18]));
        f(out, "destination_hash", &hexs(&raw[18..34]));
        f(out, "context", &context_name(raw[34]));
    } else {
        f(out, "transport_id", "-");
        f(out, "destination_hash", &hexs(&raw[2..18]));
        f(out, "context", &context_name(raw[18]));
    }
    f(out, "payload_length", &format!("{}", raw.len() - payload_at));
}

fn encrypted(out: &mut Vec<String>, b: &[Option<Vec<u8>>]) {
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    let priv_key = b[0].as_ref().unwrap();
    let ratchet_priv = b[1].as_ref();
    let raw = b[2].as_ref().unwrap();

    if raw.len() < 19 {
        return invalid(out, "short-header", &[("length", raw.len()), ("minimum_length", 19)]);
    }
    let payload = &raw[19..];
    if payload.len() < 32 + 48 {
        return invalid(out, "short-payload",
                       &[("payload_length", payload.len()), ("minimum_length", 32 + 48)]);
    }

    let ephemeral = &payload[..32];
    let tok = &payload[32..];
    let iv = &tok[..16];
    let ct = &tok[16..tok.len() - 32];
    let mac = &tok[tok.len() - 32..];

    let id = PrivateIdentity::new_from_hex_string(&hexs(priv_key)).unwrap();

    let mut eph = [0u8; 32];
    eph.copy_from_slice(ephemeral);
    let peer = PublicKey::from(eph);

    let mut agree = [0u8; 32];
    let mut ratchet_pub: Option<[u8; 32]> = None;
    match ratchet_priv {
        Some(r) => {
            agree.copy_from_slice(r);
            ratchet_pub = Some(PublicKey::from(&StaticSecret::from(agree)).to_bytes());
        }
        None => agree.copy_from_slice(&priv_key[..32]),
    }
    let shared = StaticSecret::from(agree).diffie_hellman(&peer);

    // Reticulum-rs derives through DerivedKey; the salt is the identity
    // address hash, as in the reference.
    let derived = reticulum::identity::DerivedKey::new(&shared, Some(id.address_hash().as_slice()));
    let bytes = derived.as_bytes();
    let half = bytes.len() / 2;

    let mut buf = [0u8; 1024];
    let plaintext = id.decrypt(OsRng, tok, &derived, &mut buf).ok().map(|p| p.to_vec());

    print_header(out, raw);
    f(out, "ephemeral_public", &hexs(ephemeral));
    f(out, "iv", &hexs(iv));
    f(out, "ciphertext", &hexs(ct));
    f(out, "hmac", &hexs(mac));
    f(out, "identity_hash", &hexs(id.address_hash().as_slice()));
    match ratchet_pub {
        Some(r) => f(out, "ratchet_public", &hexs(&r)),
        None => f(out, "ratchet_public", "-"),
    }
    f(out, "shared_key", &hexs(shared.as_bytes()));
    f(out, "signing_key", &hexs(&bytes[..half]));
    f(out, "encryption_key", &hexs(&bytes[half..]));
    f(out, "hmac_valid", if plaintext.is_some() { "yes" } else { "no" });
    match plaintext {
        None => {
            f(out, "plaintext_length", "-");
            f(out, "plaintext", "-");
        }
        Some(pt) => {
            f(out, "plaintext_length", &format!("{}", pt.len()));
            if pt.is_empty() { f(out, "plaintext", "-"); } else { f(out, "plaintext", &hexs(&pt)); }
        }
    }
}

// Named from Reticulum-rs's own PacketContext at
// reticulum-core/src/packet.rs:105.
fn context_name(c: u8) -> String {
    use reticulum::packet::PacketContext;
    match PacketContext::from(c) {
        PacketContext::None => "none".to_string(),
        PacketContext::PathResponse => "path_response".to_string(),
        PacketContext::KeepAlive => "keepalive".to_string(),
        PacketContext::LinkIdentify => "link_identify".to_string(),
        PacketContext::LinkClose => "link_close".to_string(),
        PacketContext::LinkProof => "link_proof".to_string(),
        PacketContext::LinkRTT => "link_rtt".to_string(),
        PacketContext::LinkRequestProof => "link_request_proof".to_string(),
        _ => format!("{:02x}", c),
    }
}

// LinkId::from(&Packet) is Reticulum-rs's own derivation, and it is the
// one entry point that needs nothing but the packet.
fn link_id_of(raw: &[u8]) -> Option<Vec<u8>> {
    use reticulum::destination::link::LinkId;
    let mut buffer = InputBuffer::new(raw);
    let packet = Packet::deserialize(&mut buffer).ok()?;
    Some(LinkId::from(&packet).as_slice().to_vec())
}

fn linkrequest(out: &mut Vec<String>, b: &[Option<Vec<u8>>]) {
    let raw = b[0].as_ref().unwrap();
    if raw.len() < 19 {
        return invalid(out, "short-header", &[("length", raw.len()), ("minimum_length", 19)]);
    }
    let payload = &raw[19..];

    // new_from_request refuses anything shorter than the two keys and
    // accepts every length above, so it is the only length rule there
    // is. reticulum-core/src/destination/link.rs:184.
    if payload.len() < 64 {
        return invalid(out, "invalid-length",
                       &[("payload_length", payload.len()), ("accepted_length", 64),
                         ("signalled_length", 67)]);
    }

    let link_id = match link_id_of(raw) {
        Some(id) => id,
        None => return invalid(out, "short-header",
                               &[("length", raw.len()), ("minimum_length", 19)]),
    };

    print_header(out, raw);
    f(out, "x25519_public", &hexs(&payload[..32]));
    f(out, "ed25519_public", &hexs(&payload[32..64]));

    // Reticulum-rs sends 64 bytes and reads no signalling: request() at
    // link.rs:214 writes the two keys and stops, and nothing anywhere
    // decodes a mode or an MTU. The bytes are shown where they are and
    // nothing is read out of them, so the MTU has no value here. The
    // mode is the one its derived key fixes: 64 bytes, so AES-256.
    if payload.len() > 64 {
        f(out, "signalling", &hexs(&payload[64..]));
    } else {
        f(out, "signalling", "-");
    }
    f(out, "mode", "aes256_cbc");
    f(out, "mtu", "-");
    f(out, "link_id", &hexs(&link_id));
}

fn linkproof(out: &mut Vec<String>, b: &[Option<Vec<u8>>]) {
    let request_raw = b[0].as_ref().unwrap();
    let identity_public = b[1].as_ref().unwrap();
    let raw = b[2].as_ref().unwrap();

    if raw.len() < 19 {
        return invalid(out, "short-header", &[("length", raw.len()), ("minimum_length", 19)]);
    }
    let payload = &raw[19..];
    if payload.len() != 96 && payload.len() != 99 {
        return invalid(out, "invalid-length",
                       &[("payload_length", payload.len()), ("accepted_length", 96),
                         ("signalled_length", 99)]);
    }

    let link_id = link_id_of(request_raw).expect("the link request does not decode");
    let signature = &payload[..64];
    let x25519_public = &payload[64..96];
    let signalling = &payload[96..];

    let signer = Identity::new_from_slices(&identity_public[..32], &identity_public[32..]);

    // Reticulum-rs has no link request proof path: nothing in
    // reticulum-core verifies one. The material is assembled as the
    // reference assembles it and handed to Reticulum-rs's own verifier,
    // so the curve and the encoding are still its own.
    let mut signed = Vec::new();
    signed.extend_from_slice(&link_id);
    signed.extend_from_slice(x25519_public);
    signed.extend_from_slice(&identity_public[32..]);
    signed.extend_from_slice(signalling);

    print_header(out, raw);
    f(out, "link_id", &hexs(&link_id));
    f(out, "link_id_match", if raw[2..18] == link_id[..] { "yes" } else { "no" });
    f(out, "signature", &hexs(signature));
    f(out, "x25519_public", &hexs(x25519_public));
    if signalling.is_empty() {
        f(out, "signalling", "-");
        f(out, "mode", "aes256_cbc");
        f(out, "mtu", "-");
    } else {
        f(out, "signalling", &hexs(signalling));
        f(out, "mode", if signalling[0] >> 5 == 1 { "aes256_cbc".to_string() }
                       else { format!("{:02x}", signalling[0] >> 5) }.as_str());
        f(out, "mtu", &format!("{}",
            ((signalling[0] as u32) << 16 | (signalling[1] as u32) << 8
             | signalling[2] as u32) & 0x1fffff));
    }
    f(out, "signer_ed25519", &hexs(&identity_public[32..]));
    f(out, "signed_data", &hexs(&signed));
    f(out, "signature_valid", if verify(&signer, signature, &signed) { "yes" } else { "no" });
}

fn verify(id: &Identity, signature: &[u8], message: &[u8]) -> bool {
    use ed25519_dalek::Signature;
    let mut sig = [0u8; 64];
    sig.copy_from_slice(signature);
    id.verifying_key.verify_strict(message, &Signature::from_bytes(&sig)).is_ok()
}

fn linkdata(out: &mut Vec<String>, b: &[Option<Vec<u8>>]) {
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    let request_raw = b[0].as_ref().unwrap();
    let responder_private = b[1].as_ref().unwrap();
    let raw = b[2].as_ref().unwrap();

    if raw.len() < 19 {
        return invalid(out, "short-header", &[("length", raw.len()), ("minimum_length", 19)]);
    }
    let payload = &raw[19..];
    let context = raw[18];
    let link_id = link_id_of(request_raw).expect("the link request does not decode");

    print_header(out, raw);
    f(out, "link_id", &hexs(&link_id));
    f(out, "link_id_match", if raw[2..18] == link_id[..] { "yes" } else { "no" });

    if context == 0xfa {
        f(out, "encrypted", "no");
        f(out, "plaintext_length", &format!("{}", payload.len()));
        if payload.is_empty() { f(out, "plaintext", "-"); } else { f(out, "plaintext", &hexs(payload)); }
        return;
    }
    f(out, "encrypted", "yes");

    let iv = &payload[..16];
    let ct = &payload[16..payload.len() - 32];
    let mac = &payload[payload.len() - 32..];

    let mut peer = [0u8; 32];
    peer.copy_from_slice(&request_raw[19..51]);
    let mut own = [0u8; 32];
    own.copy_from_slice(responder_private);
    let shared = StaticSecret::from(own).diffie_hellman(&PublicKey::from(peer));

    // The salt is the link id, as handshake passes it at link.rs:423.
    let derived = reticulum::identity::DerivedKey::new(&shared, Some(&link_id));
    let bytes = derived.as_bytes();
    let half = bytes.len() / 2;

    // decrypt wants a PrivateIdentity, and only for its key material,
    // which the derived key already supplies. Any identity serves.
    let id = PrivateIdentity::new_from_name("conformance");
    let mut buf = [0u8; 1024];
    let plaintext = id.decrypt(OsRng, payload, &derived, &mut buf).ok().map(|p| p.to_vec());

    f(out, "iv", &hexs(iv));
    f(out, "ciphertext", &hexs(ct));
    f(out, "hmac", &hexs(mac));
    f(out, "shared_key", &hexs(shared.as_bytes()));
    f(out, "signing_key", &hexs(&bytes[..half]));
    f(out, "encryption_key", &hexs(&bytes[half..]));
    f(out, "hmac_valid", if plaintext.is_some() { "yes" } else { "no" });
    match &plaintext {
        None => {
            f(out, "plaintext_length", "-");
            f(out, "plaintext", "-");
            return;
        }
        Some(pt) => {
            f(out, "plaintext_length", &format!("{}", pt.len()));
            if pt.is_empty() { f(out, "plaintext", "-"); } else { f(out, "plaintext", &hexs(pt)); }
        }
    }

    let pt = plaintext.unwrap();
    if context == 0xfb && pt.len() == 128 {
        let pub_key = &pt[..64];
        let sig = &pt[64..];
        let mut signed = Vec::new();
        signed.extend_from_slice(&link_id);
        signed.extend_from_slice(pub_key);
        let id = Identity::new_from_slices(&pub_key[..32], &pub_key[32..]);
        f(out, "identity_public", &hexs(pub_key));
        f(out, "identity_hash", &hexs(id.address_hash.as_slice()));
        f(out, "identity_signed", &hexs(&signed));
        f(out, "identity_valid", if verify(&id, sig, &signed) { "yes" } else { "no" });
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: rsret kind rawfile");
        std::process::exit(2);
    }
    let blobs = read_raw(&args[2]);
    let mut out = Vec::new();

    match args[1].as_str() {
        "identity" => identity(&mut out, &blobs),
        "keyset" => keyset(&mut out, &blobs),
        "destination" => destination(&mut out, &blobs),
        "signature" => signature(&mut out, &blobs),
        "announce" => announce(&mut out, &blobs),
        "encrypted" => encrypted(&mut out, &blobs),
        "linkrequest" => linkrequest(&mut out, &blobs),
        "linkproof" => linkproof(&mut out, &blobs),
        "linkdata" => linkdata(&mut out, &blobs),
        k => {
            eprintln!("unknown kind {}", k);
            std::process::exit(2);
        }
    }

    println!("{}", out.join("\n"));
}
