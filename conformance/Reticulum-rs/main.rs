// Conformance harness for BeechatNetworkSystemsLtd/Reticulum-rs.
//
//	rsret kind rawfile

use std::env;
use std::fs;

use reticulum::destination::{DestinationAnnounce, DestinationName};
use reticulum::hash::AddressHash;
use reticulum::identity::{Identity, PrivateIdentity};
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
        k => {
            eprintln!("unknown kind {}", k);
            std::process::exit(2);
        }
    }

    println!("{}", out.join("\n"));
}
