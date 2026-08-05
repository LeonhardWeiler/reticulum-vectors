// Conformance harness for ratspeak/rsReticulum.
//
//	rsret2 kind rawfile

use std::env;
use std::fs;

use rns_crypto::hkdf::derive_key_64;
use rns_crypto::sha::sha256;
use rns_crypto::token;
use rns_crypto::x25519::{X25519PrivateKey, X25519PublicKey};
use rns_identity::announce::AnnounceData as Announce;
use rns_identity::destination::Destination;
use rns_identity::identity::Identity;
use rns_wire::packet::Packet;
use rns_wire::flags::{DestinationType, HeaderType, PacketType, TransportType};

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
    let id = Identity::from_public_key(pk).unwrap();
    let full = id.get_public_key();
    f(out, "public_key", &hexs(&full));
    f(out, "x25519_public", &hexs(&full[0..32]));
    f(out, "ed25519_public", &hexs(&full[32..64]));
    f(out, "identity_hash", &hexs(&id.hash));
}

fn keyset(out: &mut Vec<String>, b: &[Option<Vec<u8>>]) {
    let prv = b[0].as_ref().unwrap();
    let id = Identity::from_private_key(prv).unwrap();
    let got = id.get_private_key().unwrap();
    let full = id.get_public_key();
    f(out, "private_key", &hexs(&got[..]));
    f(out, "x25519_private", &hexs(&got[0..32]));
    f(out, "ed25519_private", &hexs(&got[32..64]));
    f(out, "public_key", &hexs(&full));
    f(out, "x25519_public", &hexs(&full[0..32]));
    f(out, "ed25519_public", &hexs(&full[32..64]));
    f(out, "identity_hash", &hexs(&id.hash));
}

fn destination(out: &mut Vec<String>, b: &[Option<Vec<u8>>]) {
    let name = String::from_utf8(b[0].clone().unwrap()).unwrap();
    let (app_name, aspects) = Destination::app_and_aspects_from_name(&name);
    let expanded = Destination::expand_name(None, app_name, &aspects).unwrap();
    let nh = rns_identity::name_hash::name_hash(&expanded);

    let ih: Option<[u8; 16]> = b[1].as_ref().map(|v| {
        let mut a = [0u8; 16];
        a.copy_from_slice(v);
        a
    });
    let dh = Destination::compute_hash(&nh, ih.as_ref());

    f(out, "name", &hexs(b[0].as_ref().unwrap()));
    f(out, "app_name", &hexs(app_name.as_bytes()));
    for a in &aspects {
        f(out, "aspect", &hexs(a.as_bytes()));
    }
    f(out, "name_hash", &hexs(&nh));
    match &ih {
        Some(h) => f(out, "identity_hash", &hexs(h)),
        None => f(out, "identity_hash", "-"),
    }
    f(out, "destination_hash", &hexs(&dh));
}

fn signature(out: &mut Vec<String>, b: &[Option<Vec<u8>>]) {
    let pk = b[0].as_ref().unwrap();
    let msg = b[1].as_ref().unwrap();
    let sig = b[2].as_ref().unwrap();
    let id = Identity::from_public_key(pk).unwrap();
    let mut s = [0u8; 64];
    s.copy_from_slice(sig);

    f(out, "ed25519_public", &hexs(&pk[32..]));
    f(out, "message_length", &format!("{}", msg.len()));
    f(out, "message_sha256", &hexs(&sha256(msg)));
    f(out, "signature", &hexs(sig));
    f(out, "valid", if id.verify(msg, &s) { "yes" } else { "no" });
}

fn invalid(out: &mut Vec<String>, reason: &str, pairs: &[(&str, usize)]) {
    f(out, "invalid", reason);
    for (k, v) in pairs {
        f(out, k, &format!("{}", v));
    }
}

fn dest_type_name(t: DestinationType) -> &'static str {
    match t {
        DestinationType::Single => "single",
        DestinationType::Group => "group",
        DestinationType::Plain => "plain",
        DestinationType::Link => "link",
    }
}

fn packet_type_name(t: PacketType) -> &'static str {
    match t {
        PacketType::Data => "data",
        PacketType::Announce => "announce",
        PacketType::LinkRequest => "linkrequest",
        PacketType::Proof => "proof",
    }
}

fn xport_type_name(t: TransportType) -> &'static str {
    match t {
        TransportType::Broadcast => "broadcast",
        TransportType::Transport => "transport",
    }
}

fn announce(out: &mut Vec<String>, b: &[Option<Vec<u8>>]) {
    let raw = b[0].as_ref().unwrap();
    if raw.len() < 2 {
        return invalid(out, "short-header", &[("length", raw.len()), ("minimum_length", 2)]);
    }

    // No hop limit check here: whether from_raw applies one is what the
    // vector at the limit is testing.
    let p = match Packet::from_raw(raw) {
        Ok(p) => p,
        Err(_) => return invalid(out, "short-header",
                                 &[("length", raw.len()), ("minimum_length", 19)]),
    };

    let h = &p.header;
    let has_ratchet = h.flags.context_flag;
    let payload = p.data();

    let a = match Announce::unpack(payload, has_ratchet) {
        Ok(a) => a,
        Err(_) => {
            let mut m = 64 + 10 + 10 + 64;
            if has_ratchet { m += 32; }
            return invalid(out, "short-payload",
                           &[("payload_length", payload.len()), ("minimum_length", m)]);
        }
    };

    let id = Identity::from_public_key(&a.public_key).unwrap();
    let expected = Destination::compute_hash(&a.name_hash, Some(&id.hash));

    let app_data = a.app_data.clone().unwrap_or_default();
    let mut signed = Vec::new();
    signed.extend_from_slice(&h.destination_hash);
    signed.extend_from_slice(&a.public_key);
    signed.extend_from_slice(&a.name_hash);
    signed.extend_from_slice(&a.random_hash);
    if let Some(r) = a.ratchet {
        signed.extend_from_slice(&r);
    }
    signed.extend_from_slice(&app_data);

    f(out, "flags", &format!("{:02x}", raw[0]));
    f(
        out,
        "header_type",
        match h.flags.header_type {
            HeaderType::Header1 => "1",
            HeaderType::Header2 => "2",
        },
    );
    f(out, "context_flag", if has_ratchet { "set" } else { "unset" });
    f(out, "transport_type", xport_type_name(h.flags.transport_type));
    f(out, "destination_type", dest_type_name(h.flags.destination_type));
    f(out, "packet_type", packet_type_name(h.flags.packet_type));
    f(out, "hops", &format!("{}", h.hops));
    match h.transport_id {
        Some(t) => f(out, "transport_id", &hexs(&t)),
        None => f(out, "transport_id", "-"),
    }
    f(out, "destination_hash", &hexs(&h.destination_hash));
    f(
        out,
        "context",
        match h.context.to_byte() {
            0x00 => "none".to_string(),
            0x0b => "path_response".to_string(),
            c => format!("{:02x}", c),
        }
        .as_str(),
    );
    f(out, "payload_length", &format!("{}", payload.len()));
    f(out, "public_key", &hexs(&a.public_key));
    f(out, "name_hash", &hexs(&a.name_hash));
    f(out, "random_hash", &hexs(&a.random_hash));
    match a.ratchet {
        Some(r) => f(out, "ratchet", &hexs(&r)),
        None => f(out, "ratchet", "-"),
    }
    f(out, "signature", &hexs(&a.signature));
    if app_data.is_empty() {
        f(out, "app_data", "-");
    } else {
        f(out, "app_data", &hexs(&app_data));
    }
    f(out, "identity_hash", &hexs(&id.hash));
    f(out, "expected_hash", &hexs(&expected));
    f(
        out,
        "destination_match",
        if h.destination_hash == expected { "yes" } else { "no" },
    );
    f(out, "signed_data", &hexs(&signed));

    // Verdict from the implementation's own validator.
    let ok = a.verify_signature(&h.destination_hash).is_ok();
    f(out, "signature_valid", if ok { "yes" } else { "no" });
}

// rsReticulum exposes no entry point that yields the header fields on
// their own, so this mirrors what announce() above already does.
fn print_header(out: &mut Vec<String>, p: &Packet, raw: &[u8]) {
    let h = &p.header;
    f(out, "flags", &format!("{:02x}", raw[0]));
    f(out, "header_type", match h.flags.header_type {
        HeaderType::Header1 => "1",
        HeaderType::Header2 => "2",
    });
    f(out, "context_flag", if h.flags.context_flag { "set" } else { "unset" });
    f(out, "transport_type", xport_type_name(h.flags.transport_type));
    f(out, "destination_type", dest_type_name(h.flags.destination_type));
    f(out, "packet_type", packet_type_name(h.flags.packet_type));
    f(out, "hops", &format!("{}", h.hops));
    match h.transport_id {
        Some(t) => f(out, "transport_id", &hexs(&t)),
        None => f(out, "transport_id", "-"),
    }
    f(out, "destination_hash", &hexs(&h.destination_hash));
    f(out, "context", match h.context.to_byte() {
        0x00 => "none".to_string(),
        0x0b => "path_response".to_string(),
        c => format!("{:02x}", c),
    }.as_str());
    f(out, "payload_length", &format!("{}", p.data().len()));
}

fn encrypted(out: &mut Vec<String>, b: &[Option<Vec<u8>>]) {
    let priv_key = b[0].as_ref().unwrap();
    let ratchet_priv = b[1].as_ref();
    let raw = b[2].as_ref().unwrap();

    if raw.len() < 2 {
        return invalid(out, "short-header", &[("length", raw.len()), ("minimum_length", 2)]);
    }
    let p = match Packet::from_raw(raw) {
        Ok(p) => p,
        Err(_) => return invalid(out, "short-header",
                                 &[("length", raw.len()), ("minimum_length", 19)]),
    };

    let payload = p.data();
    if payload.len() < 32 + 48 {
        return invalid(out, "short-payload",
                       &[("payload_length", payload.len()), ("minimum_length", 32 + 48)]);
    }

    let ephemeral = &payload[..32];
    let tok = &payload[32..];
    let iv = &tok[..16];
    let ct = &tok[16..tok.len() - 32];
    let mac = &tok[tok.len() - 32..];

    let id = Identity::from_private_key(priv_key).unwrap();

    let mut eph = [0u8; 32];
    eph.copy_from_slice(ephemeral);
    let peer = X25519PublicKey::from_bytes(&eph);

    let mut agree = [0u8; 32];
    let mut ratchet_pub: Option<[u8; 32]> = None;
    match ratchet_priv {
        Some(r) => {
            agree.copy_from_slice(r);
            ratchet_pub = Some(X25519PrivateKey::from_bytes(&agree).public_key().to_bytes());
        }
        None => agree.copy_from_slice(&priv_key[..32]),
    }
    let shared = X25519PrivateKey::from_bytes(&agree).exchange(&peer);

    let derived = derive_key_64(&shared, &id.hash).unwrap();
    let half = derived.len() / 2;

    let hmac_ok = token::decrypt(tok, &derived).is_ok();

    let ratchets_owned: Vec<[u8; 32]> = match ratchet_priv {
        Some(r) => {
            let mut a = [0u8; 32];
            a.copy_from_slice(r);
            vec![a]
        }
        None => vec![],
    };
    let ratchet_refs: Vec<&[u8; 32]> = ratchets_owned.iter().collect();
    let plaintext = id
        .decrypt(payload, if ratchet_refs.is_empty() { None } else { Some(&ratchet_refs) }, false)
        .ok();

    print_header(out, &p, raw);
    f(out, "ephemeral_public", &hexs(ephemeral));
    f(out, "iv", &hexs(iv));
    f(out, "ciphertext", &hexs(ct));
    f(out, "hmac", &hexs(mac));
    f(out, "identity_hash", &hexs(&id.hash));
    match ratchet_pub {
        Some(r) => f(out, "ratchet_public", &hexs(&r)),
        None => f(out, "ratchet_public", "-"),
    }
    f(out, "shared_key", &hexs(&shared));
    f(out, "signing_key", &hexs(&derived[..half]));
    f(out, "encryption_key", &hexs(&derived[half..]));
    f(out, "hmac_valid", if hmac_ok { "yes" } else { "no" });
    match plaintext {
        None => {
            f(out, "plaintext_length", "-");
            f(out, "plaintext", "-");
        }
        Some(pt) => {
            f(out, "plaintext_length", &format!("{}", pt.len()));
            if pt.is_empty() {
                f(out, "plaintext", "-");
            } else {
                f(out, "plaintext", &hexs(&pt));
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: rsret2 kind rawfile");
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
        k => {
            eprintln!("unknown kind {}", k);
            std::process::exit(2);
        }
    }

    println!("{}", out.join("\n"));
}
