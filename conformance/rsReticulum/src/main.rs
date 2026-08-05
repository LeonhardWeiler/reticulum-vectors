// Conformance harness for ratspeak/rsReticulum.
//
//	rsret2 kind rawfile
//
// See ../README for what a harness may and may not do.

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
    f(out, "context", &context_name(h.context.to_byte()));
    f(out, "payload_length", &format!("{}", p.data().len()));
}

// The other direction of signature: the signature is produced, not
// handed in. crates/rns-identity/src/identity.rs:277.
fn sign(out: &mut Vec<String>, b: &[Option<Vec<u8>>]) {
    let prv = b[0].as_ref().unwrap();
    let msg = b[1].as_ref().unwrap();
    let id = Identity::from_private_key(prv).unwrap();

    f(out, "private_key", &hexs(prv));
    f(out, "ed25519_private", &hexs(&prv[32..]));
    f(out, "ed25519_public", &hexs(&id.get_public_key()[32..64]));
    f(out, "message_length", &format!("{}", msg.len()));
    f(out, "message_sha256", &hexs(&sha256(msg)));
    f(out, "signature", &hexs(&id.sign(msg).unwrap()));
}

fn encrypted(out: &mut Vec<String>, b: &[Option<Vec<u8>>]) {
    let priv_key = b[0].as_ref().unwrap();
    let ratchet_priv = b[1].as_ref();
    let raw = b[2].as_ref().unwrap();

    // Echoes of the input lines, so that expect holds every byte of raw.
    // Not a claim about rsReticulum: the harness was handed these.
    f(out, "recipient_private", &hexs(priv_key));
    match ratchet_priv {
        Some(r) => f(out, "ratchet_private", &hexs(r)),
        None => f(out, "ratchet_private", "-"),
    }

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

// Named from rsReticulum's own PacketContext at
// crates/rns-wire/src/context.rs:7.
fn context_name(c: u8) -> String {
    use rns_wire::context::PacketContext;
    match PacketContext::from_byte(c) {
        PacketContext::None => "none".to_string(),
        PacketContext::PathResponse => "path_response".to_string(),
        PacketContext::Keepalive => "keepalive".to_string(),
        PacketContext::LinkIdentify => "link_identify".to_string(),
        PacketContext::LinkClose => "link_close".to_string(),
        PacketContext::LinkProof => "link_proof".to_string(),
        PacketContext::Lrrtt => "link_rtt".to_string(),
        PacketContext::Lrproof => "link_request_proof".to_string(),
        _ => format!("{:02x}", c),
    }
}

fn mode_name(mode: u8) -> String {
    if mode == 1 { "aes256_cbc".to_string() } else { format!("{:02x}", mode) }
}

fn link_id_of(raw: &[u8], p: &Packet) -> [u8; 16] {
    rns_wire::hash::link_id_from_raw(raw, p.header.flags.header_type)
}

fn linkrequest(out: &mut Vec<String>, b: &[Option<Vec<u8>>]) {
    use rns_link::handshake::LinkRequestData;

    let raw = b[0].as_ref().unwrap();
    let p = match Packet::from_raw(raw) {
        Ok(p) => p,
        Err(_) => return invalid(out, "short-header",
                                 &[("length", raw.len()), ("minimum_length", 19)]),
    };
    let payload = p.data();

    let request = match LinkRequestData::unpack(payload) {
        Ok(r) => r,
        Err(_) => return invalid(out, "invalid-length",
                                 &[("payload_length", payload.len()), ("accepted_length", 64),
                                   ("signalled_length", 67)]),
    };

    let signalled = payload.len() == 67;
    print_header(out, &p, raw);
    f(out, "x25519_public", &hexs(&request.peer_x25519_pub));
    f(out, "ed25519_public", &hexs(&request.peer_ed25519_pub));
    if signalled {
        f(out, "signalling", &hexs(&payload[64..]));
    } else {
        f(out, "signalling", "-");
    }
    f(out, "mode", &mode_name(request.signalling.mode));

    // unpack fills in the default MTU when nothing was signalled, so
    // the field is shown only where the packet carried one.
    if signalled {
        f(out, "mtu", &format!("{}", request.signalling.mtu));
    } else {
        f(out, "mtu", "-");
    }
    f(out, "link_id", &hexs(&link_id_of(raw, &p)));
}

fn linkproof(out: &mut Vec<String>, b: &[Option<Vec<u8>>]) {
    use rns_link::handshake::LinkProofData;

    let request_raw = b[0].as_ref().unwrap();
    let identity_public = b[1].as_ref().unwrap();
    let raw = b[2].as_ref().unwrap();

    f(out, "link_request", &hexs(request_raw));
    f(out, "signer_public", &hexs(identity_public));

    let p = match Packet::from_raw(raw) {
        Ok(p) => p,
        Err(_) => return invalid(out, "short-header",
                                 &[("length", raw.len()), ("minimum_length", 19)]),
    };
    let payload = p.data();

    let proof = match LinkProofData::unpack(payload) {
        Ok(r) => r,
        Err(_) => return invalid(out, "invalid-length",
                                 &[("payload_length", payload.len()), ("accepted_length", 96),
                                   ("signalled_length", 99)]),
    };

    let request = Packet::from_raw(request_raw).expect("the link request does not decode");
    let link_id = link_id_of(request_raw, &request);

    let mut peer_ed = [0u8; 32];
    peer_ed.copy_from_slice(&identity_public[32..]);
    let verify_key = rns_crypto::ed25519::Ed25519PublicKey::from_bytes(&peer_ed).unwrap();

    // validate assembles the signed material itself and returns only a
    // verdict, so the same four parts are assembled here to be printed.
    // rsReticulum always appends its signalling, including the default
    // it substitutes for a 96-byte proof: handshake.rs:245.
    let signalled = payload.len() == 99;
    let mut signed = Vec::new();
    signed.extend_from_slice(&link_id);
    signed.extend_from_slice(&proof.responder_x25519_pub);
    signed.extend_from_slice(&peer_ed);
    signed.extend_from_slice(&proof.signalling.pack());

    print_header(out, &p, raw);
    f(out, "link_id", &hexs(&link_id));
    f(out, "link_id_match",
      if p.header.destination_hash == link_id { "yes" } else { "no" });
    f(out, "signature", &hexs(&proof.signature));
    f(out, "x25519_public", &hexs(&proof.responder_x25519_pub));
    if signalled {
        f(out, "signalling", &hexs(&payload[96..]));
        f(out, "mode", &mode_name(proof.signalling.mode));
        f(out, "mtu", &format!("{}", proof.signalling.mtu));
    } else {
        f(out, "signalling", "-");
        f(out, "mode", &mode_name(proof.signalling.mode));
        f(out, "mtu", "-");
    }
    f(out, "signer_ed25519", &hexs(&peer_ed));
    f(out, "signed_data", &hexs(&signed));
    f(out, "signature_valid",
      if proof.validate(&verify_key, &link_id, &peer_ed) { "yes" } else { "no" });
}

fn linkdata(out: &mut Vec<String>, b: &[Option<Vec<u8>>]) {
    use rns_link::constants::MODE_AES256_CBC;
    use rns_link::encryption::link_decrypt;
    use rns_link::key_derivation::LinkKeys;

    let request_raw = b[0].as_ref().unwrap();
    let responder_private = b[1].as_ref().unwrap();
    let raw = b[2].as_ref().unwrap();

    f(out, "link_request", &hexs(request_raw));
    f(out, "responder_private", &hexs(responder_private));

    let p = match Packet::from_raw(raw) {
        Ok(p) => p,
        Err(_) => return invalid(out, "short-header",
                                 &[("length", raw.len()), ("minimum_length", 19)]),
    };
    let payload = p.data().to_vec();

    let request = Packet::from_raw(request_raw).expect("the link request does not decode");
    let link_id = link_id_of(request_raw, &request);

    print_header(out, &p, raw);
    f(out, "link_id", &hexs(&link_id));
    f(out, "link_id_match",
      if p.header.destination_hash == link_id { "yes" } else { "no" });

    if p.header.context.to_byte() == 0xfa {
        f(out, "encrypted", "no");
        f(out, "plaintext_length", &format!("{}", payload.len()));
        if payload.is_empty() { f(out, "plaintext", "-"); }
        else { f(out, "plaintext", &hexs(&payload)); }
        return;
    }
    f(out, "encrypted", "yes");

    let iv = &payload[..16];
    let ct = &payload[16..payload.len() - 32];
    let mac = &payload[payload.len() - 32..];

    let mut prv = [0u8; 32];
    prv.copy_from_slice(responder_private);
    let mut peer = [0u8; 32];
    peer.copy_from_slice(&request.data()[..32]);

    let peer_key = X25519PublicKey::from_bytes(&peer);
    let own_key = X25519PrivateKey::from_bytes(&prv);
    let keys = LinkKeys::derive(&own_key, &peer_key, &link_id, MODE_AES256_CBC).unwrap();
    let plaintext = link_decrypt(&keys, &payload).ok();

    // LinkKeys keeps the agreement to itself, so it is repeated through
    // rsReticulum's own curve wrapper.
    let shared = own_key.exchange(&peer_key);

    f(out, "iv", &hexs(iv));
    f(out, "ciphertext", &hexs(ct));
    f(out, "hmac", &hexs(mac));
    f(out, "shared_key", &hexs(&shared));
    f(out, "signing_key", &hexs(&keys.signing_key));
    f(out, "encryption_key", &hexs(&keys.encryption_key));
    f(out, "hmac_valid", if plaintext.is_some() { "yes" } else { "no" });

    let pt = match plaintext {
        None => {
            f(out, "plaintext_length", "-");
            f(out, "plaintext", "-");
            return;
        }
        Some(pt) => {
            f(out, "plaintext_length", &format!("{}", pt.len()));
            if pt.is_empty() { f(out, "plaintext", "-"); } else { f(out, "plaintext", &hexs(&pt)); }
            pt
        }
    };

    if p.header.context.to_byte() == 0xfb && pt.len() == 128 {
        let pub_key = &pt[..64];
        let sig = &pt[64..];
        let mut signed = Vec::new();
        signed.extend_from_slice(&link_id);
        signed.extend_from_slice(pub_key);

        let mut ed = [0u8; 32];
        ed.copy_from_slice(&pub_key[32..]);
        let key = rns_crypto::ed25519::Ed25519PublicKey::from_bytes(&ed).unwrap();
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(sig);

        f(out, "identity_public", &hexs(pub_key));
        f(out, "identity_hash", &hexs(&sha256(pub_key)[..16]));
        f(out, "identity_signed", &hexs(&signed));
        f(out, "identity_valid",
          if key.verify(&signed, &sig_bytes).is_ok() { "yes" } else { "no" });
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
        "sign" => sign(&mut out, &blobs),
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
