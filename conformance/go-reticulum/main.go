// Conformance harness for svanichkin/go-reticulum.
//
//	goret kind rawfile
//
// See ../README for what a harness may and may not do.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"strings"

	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/binary"

	"github.com/svanichkin/go-reticulum/rns"
	Cryptography "github.com/svanichkin/go-reticulum/rns/cryptography"
	umsgpack "github.com/svanichkin/go-reticulum/rns/vendor"
)

const (
	W        = 18
	keySize  = 64
	nameLen  = 10
	randLen  = 10
	sigLen   = 64
	ratchLen = 32
	addrLen  = 16
)

// How long a header has to be, following Packet.Unpack at
// rns/packet.go:425. It tests no length: it slices at 2+dstLen+1 or at
// 2+2*dstLen+1 by the header type bit and lets the recover catch what
// is not there, so the bound below is the offset it indexes and not a
// constant this harness chose. ReticulumTruncatedHashLength is
// go-reticulum's own.
//
// The 2 the callers guard on is that same rule one byte earlier:
// Unpack reads Raw[1] for the hops before it reads the header type at
// all, so a one-byte frame dies at the second byte and 2 is the offset
// it indexed. It is a constant here because the byte that would move
// it is the byte that is missing.
func headerMinimum(raw []byte) int {
	dstLen := rns.ReticulumTruncatedHashLength / 8
	if (raw[0]&0b01000000)>>6 == rns.HeaderType2 {
		return 2 + 2*dstLen + 1
	}
	return 2 + dstLen + 1
}

var out []string

func f(name, value string) { out = append(out, fmt.Sprintf("%-*s %s", W, name, value)) }

// An empty byte string prints as "-", as cmd/dump's field_hex does.
// Hex cannot spell it, and a name followed by nothing cannot be told
// from a truncated line.
func hx(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return hex.EncodeToString(b)
}

func mpBin(v any) string {
	b, ok := v.([]byte)
	if !ok {
		return "-"
	}
	return hx(b)
}

func readRaw(path string) [][]byte {
	body, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var blobs [][]byte
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "-" {
			blobs = append(blobs, nil)
			continue
		}
		b, err := hex.DecodeString(line)
		if err != nil {
			panic(err)
		}
		blobs = append(blobs, b)
	}
	return blobs
}

func identity(b [][]byte) {
	id := &rns.Identity{}
	if err := id.LoadPublicKey(b[0]); err != nil {
		panic(err)
	}
	pub := id.GetPublicKey()
	f("public_key", hx(pub))
	f("x25519_public", hx(pub[:32]))
	f("ed25519_public", hx(pub[32:]))
	f("identity_hash", hx(id.Hash))
}

func keyset(b [][]byte) {
	id, err := rns.IdentityFromBytes(b[0])
	if err != nil {
		panic(err)
	}
	prv, pub := id.GetPrivateKey(), id.GetPublicKey()
	f("private_key", hx(prv))
	f("x25519_private", hx(prv[:32]))
	f("ed25519_private", hx(prv[32:]))
	f("public_key", hx(pub))
	f("x25519_public", hx(pub[:32]))
	f("ed25519_public", hx(pub[32:]))
	f("identity_hash", hx(id.Hash))
}

func destination(b [][]byte) {
	name := string(b[0])
	parts := strings.Split(name, ".")
	appName, aspects := parts[0], parts[1:]

	d := &rns.Destination{}
	expanded, err := d.ExpandName(nil, appName, aspects...)
	if err != nil {
		panic(err)
	}
	nameHash := rns.FullHash([]byte(expanded))[:nameLen]

	// HashFromNameAndIdentity takes an *Identity; the vector supplies
	// only the identity hash, and the derivation uses nothing else.
	var id *rns.Identity
	if b[1] != nil {
		id = &rns.Identity{Hash: b[1]}
	}
	dh, err := d.HashFromNameAndIdentity(name, id)
	if err != nil {
		panic(err)
	}

	f("name", hx(b[0]))
	f("app_name", hx([]byte(appName)))
	for _, a := range aspects {
		f("aspect", hx([]byte(a)))
	}
	f("name_hash", hx(nameHash))
	f("identity_hash", hx(b[1]))
	f("destination_hash", hx(dh))
}

func signature(b [][]byte) {
	id := &rns.Identity{}
	if err := id.LoadPublicKey(b[0]); err != nil {
		panic(err)
	}
	digest := sha256.Sum256(b[1])
	f("ed25519_public", hx(b[0][32:]))
	f("message_length", fmt.Sprintf("%d", len(b[1])))
	f("message_sha256", hx(digest[:]))
	f("signature", hx(b[2]))
	if id.Validate(b[2], b[1]) {
		f("valid", "yes")
	} else {
		f("valid", "no")
	}
}

var destTypes = []string{"single", "group", "plain", "link"}
var packetTypes = []string{"data", "announce", "linkrequest", "proof"}
var xportTypes = []string{"broadcast", "transport", "relay", "tunnel"}

// The other direction of signature: the signature is produced, not
// handed in. rns/identity.go:900.
func sign(b [][]byte) {
	id, err := rns.IdentityFromBytes(b[0])
	if err != nil {
		panic(err)
	}
	sig, err := id.Sign(b[1])
	if err != nil {
		panic(err)
	}
	prv := id.GetPrivateKey()
	digest := sha256.Sum256(b[1])
	f("private_key", hx(prv))
	f("ed25519_private", hx(prv[32:]))
	f("ed25519_public", hx(id.GetPublicKey()[32:]))
	f("message_length", fmt.Sprintf("%d", len(b[1])))
	f("message_sha256", hx(digest[:]))
	f("signature", hx(sig))
}

// The fourth packet type. go-reticulum has a proof validator with
// exported fields, so signature_valid is its own accept or reject over
// the whole proof rather than a bare signature check.
// rns/packet.go:743.
func proof(b [][]byte) {
	provedRaw, signerPublic, raw := b[0], b[1], b[2]

	f("proved_packet", hx(provedRaw))
	f("signer_public", hx(signerPublic))

	proved := &rns.Packet{Raw: provedRaw}
	if !proved.Unpack() {
		panic("the proved packet does not decode")
	}
	p := &rns.Packet{Raw: raw}
	if !p.Unpack() {
		invalid("short-header", [2]interface{}{"length", len(raw)}, [2]interface{}{"minimum_length", headerMinimum(raw)})
		return
	}
	printHeader(p, raw)

	id := &rns.Identity{}
	if len(signerPublic) == 64 {
		if err := id.LoadPublicKey(signerPublic); err != nil {
			panic(err)
		}
	}

	payload := p.Data
	explicit := len(payload) == 32+sigLen
	packetHash := proved.GetHash()
	signature := payload
	if explicit {
		signature = payload[32:]
	}

	receipt := &rns.PacketReceipt{
		Hash:        packetHash,
		Destination: &rns.Destination{Identity: id},
	}

	f("form", map[bool]string{true: "explicit", false: "implicit"}[explicit])
	f("packet_hash", hx(packetHash))
	if explicit {
		f("proof_hash", hx(payload[:32]))
	} else {
		f("proof_hash", "-")
	}
	f("hash_match", yesNo(!explicit || bytes.Equal(payload[:32], packetHash)))

	// On a link the proof is addressed to the link id and verified
	// under a single Ed25519 public. go-reticulum has that path, at
	// packet.go:697 validateLinkProof through link.go:2259
	// Link.Validate, but it reaches it through a Link whose peerSigPub
	// is unexported, so the key goes to the same ed25519.Verify that
	// Link.Validate calls.
	if p.DestinationType == 3 {
		f("link_id", hx(proved.DestinationHash))
		f("link_id_match", yesNo(bytes.Equal(p.DestinationHash, proved.DestinationHash)))
		f("signature", hx(signature))
		f("signer_ed25519", hx(signerPublic))
		f("signature_valid", yesNo(ed25519.Verify(ed25519.PublicKey(signerPublic), packetHash, signature)))
		return
	}

	f("proof_destination", hx(packetHash[:addrLen]))
	f("destination_match", yesNo(bytes.Equal(p.DestinationHash, packetHash[:addrLen])))
	f("signature", hx(signature))
	f("signer_ed25519", hx(signerPublic[32:]))
	f("signature_valid", yesNo(receipt.ValidateProof(payload, p)))
}

func invalid(reason string, pairs ...[2]interface{}) {
	f("invalid", reason)
	for _, kv := range pairs {
		f(kv[0].(string), fmt.Sprintf("%d", kv[1]))
	}
}

func announce(b [][]byte) {
	raw := b[0]
	if len(raw) < 2 {
		invalid("short-header", [2]interface{}{"length", len(raw)}, [2]interface{}{"minimum_length", 2})
		return
	}

	p := &rns.Packet{Raw: raw}
	if !p.Unpack() {
		invalid("short-header", [2]interface{}{"length", len(raw)}, [2]interface{}{"minimum_length", headerMinimum(raw)})
		return
	}

	// No hop limit check: Packet.Unpack has none. Adding one here
	// would hide that.

	payload := p.Data
	min := keySize + nameLen + randLen + sigLen
	if p.ContextFlag == rns.FlagSet {
		min += ratchLen
	}
	if len(payload) < min {
		invalid("short-payload", [2]interface{}{"payload_length", len(payload)}, [2]interface{}{"minimum_length", min})
		return
	}

	// Follows rns/identity.go:652-696.
	at := 0
	publicKey := payload[at : at+keySize]
	at += keySize
	nameHash := payload[at : at+nameLen]
	at += nameLen
	randomHash := payload[at : at+randLen]
	at += randLen
	var ratchet []byte
	if p.ContextFlag == rns.FlagSet {
		ratchet = payload[at : at+ratchLen]
		at += ratchLen
	}
	sig := payload[at : at+sigLen]
	at += sigLen
	appData := payload[at:]

	signed := append([]byte{}, p.DestinationHash...)
	signed = append(signed, publicKey...)
	signed = append(signed, nameHash...)
	signed = append(signed, randomHash...)
	signed = append(signed, ratchet...)
	signed = append(signed, appData...)

	announced := &rns.Identity{}
	if err := announced.LoadPublicKey(publicKey); err != nil {
		panic(err)
	}
	material := append(append([]byte{}, nameHash...), announced.Hash...)
	expected := rns.FullHash(material)[:addrLen]

	f("flags", fmt.Sprintf("%02x", raw[0]))
	f("header_type", fmt.Sprintf("%d", p.HeaderType+1))
	if p.ContextFlag == rns.FlagSet {
		f("context_flag", "set")
	} else {
		f("context_flag", "unset")
	}
	f("transport_type", xportTypes[p.TransportType])
	f("destination_type", destTypes[p.DestinationType])
	f("packet_type", packetTypes[p.PacketType])
	f("hops", fmt.Sprintf("%d", p.Hops))
	if p.HeaderType == rns.HeaderType2 {
		f("transport_id", hx(p.TransportID))
	} else {
		f("transport_id", "-")
	}
	f("destination_hash", hx(p.DestinationHash))
	switch p.Context {
	case 0x00:
		f("context", "none")
	case 0x0b:
		f("context", "path_response")
	default:
		f("context", fmt.Sprintf("%02x", p.Context))
	}
	f("payload_length", fmt.Sprintf("%d", len(payload)))
	f("public_key", hx(publicKey))
	f("name_hash", hx(nameHash))
	f("random_hash", hx(randomHash))
	if ratchet != nil {
		f("ratchet", hx(ratchet))
	} else {
		f("ratchet", "-")
	}
	f("signature", hx(sig))
	if len(appData) > 0 {
		f("app_data", hx(appData))
	} else {
		f("app_data", "-")
	}
	f("identity_hash", hx(announced.Hash))
	f("expected_hash", hx(expected))
	if bytes.Equal(p.DestinationHash, expected) {
		f("destination_match", "yes")
	} else {
		f("destination_match", "no")
	}
	f("signed_data", hx(signed))
	if announced.Validate(sig, signed) {
		f("signature_valid", "yes")
	} else {
		f("signature_valid", "no")
	}
}

// go-reticulum exposes no entry point that yields the header fields on
// their own, so this mirrors what announce() above already does.
func printHeader(p *rns.Packet, raw []byte) {
	f("flags", fmt.Sprintf("%02x", raw[0]))
	f("header_type", fmt.Sprintf("%d", p.HeaderType+1))
	if p.ContextFlag == rns.FlagSet {
		f("context_flag", "set")
	} else {
		f("context_flag", "unset")
	}
	f("transport_type", xportTypes[p.TransportType])
	f("destination_type", destTypes[p.DestinationType])
	f("packet_type", packetTypes[p.PacketType])
	f("hops", fmt.Sprintf("%d", p.Hops))
	if p.HeaderType == rns.HeaderType2 {
		f("transport_id", hx(p.TransportID))
	} else {
		f("transport_id", "-")
	}
	f("destination_hash", hx(p.DestinationHash))
	f("context", contextName(p.Context))
	f("payload_length", fmt.Sprintf("%d", len(p.Data)))
}

// Named from rns's own context constants at rns/packet.go:36-49.
func contextName(c byte) string {
	switch c {
	case rns.PacketCtxNone:
		return "none"
	case rns.PacketCtxResource:
		return "resource"
	case rns.PacketCtxResourceAdv:
		return "resource_adv"
	case rns.PacketCtxResourceReq:
		return "resource_req"
	case rns.PacketCtxResourceHMU:
		return "resource_hmu"
	case rns.PacketCtxResourcePrf:
		return "resource_prf"
	case rns.PacketCtxResourceICL:
		return "resource_icl"
	case rns.PacketCtxResourceRCL:
		return "resource_rcl"
	case rns.PacketCtxRequest:
		return "request"
	case rns.PacketCtxResponse:
		return "response"
	case rns.PacketCtxPathResponse:
		return "path_response"
	case rns.PacketCtxChannel:
		return "channel"
	case rns.PacketCtxKeepalive:
		return "keepalive"
	case rns.PacketCtxLinkIdentify:
		return "link_identify"
	case rns.PacketCtxLinkClose:
		return "link_close"
	case rns.PacketCtxLinkProof:
		return "link_proof"
	case rns.PacketCtxLRRTT:
		return "link_rtt"
	case rns.PacketCtxLRProof:
		return "link_request_proof"
	}
	return fmt.Sprintf("%02x", c)
}

func encrypted(b [][]byte) {
	priv, ratchetPriv, raw := b[0], b[1], b[2]

	// Echoes of the input lines, so that expect holds every byte of
	// raw. Not a claim about go-reticulum: the harness was handed these.
	f("recipient_private", hx(priv))
	f("ratchet_private", hx(ratchetPriv))

	if len(raw) < 2 {
		invalid("short-header", [2]interface{}{"length", len(raw)}, [2]interface{}{"minimum_length", 2})
		return
	}
	p := &rns.Packet{Raw: raw}
	if !p.Unpack() {
		invalid("short-header", [2]interface{}{"length", len(raw)}, [2]interface{}{"minimum_length", headerMinimum(raw)})
		return
	}

	payload := p.Data
	min := 32 + 48
	if len(payload) < min {
		invalid("short-payload", [2]interface{}{"payload_length", len(payload)}, [2]interface{}{"minimum_length", min})
		return
	}

	ephemeral := payload[:32]
	token := payload[32:]
	iv := token[:16]
	ct := token[16 : len(token)-32]
	mac := token[len(token)-32:]

	id, err := rns.IdentityFromBytes(priv)
	if err != nil {
		panic(err)
	}

	// The agreement uses the standard library curve, because the one
	// go-reticulum holds is unexported. Everything after it is its own
	// code: HKDF, the token, and Decrypt.
	curve := ecdh.X25519()
	agree := priv[:32]
	var ratchetPub []byte
	if ratchetPriv != nil {
		agree = ratchetPriv
		rp, e := curve.NewPrivateKey(ratchetPriv)
		if e != nil {
			panic(e)
		}
		ratchetPub = rp.PublicKey().Bytes()
	}
	sk, err := curve.NewPrivateKey(agree)
	if err != nil {
		panic(err)
	}
	pp, err := curve.NewPublicKey(ephemeral)
	if err != nil {
		panic(err)
	}
	// A refused agreement is a result, not a harness error. This curve
	// refuses a point of small order rather than returning the all-zero
	// secret, which is what the pinned backend does, and everything
	// after the agreement is then unreachable rather than wrong.
	shared, err := sk.ECDH(pp)
	if err != nil {
		printHeader(p, raw)
		f("ephemeral_public", hx(ephemeral))
		f("iv", hx(iv))
		f("ciphertext", hx(ct))
		f("hmac", hx(mac))
		f("identity_hash", hx(id.Hash))
		f("ratchet_public", hx(ratchetPub))
		for _, n := range []string{"shared_key", "signing_key", "encryption_key",
			"hmac_valid", "plaintext_length", "plaintext"} {
			f(n, "-")
		}
		return
	}

	// derivedKeyLen is 64 at rns/identity.go:28, transcribed here
	// because it is not exported.
	derived, err := Cryptography.HKDF(64, shared, id.GetSalt(), id.GetContext())
	if err != nil {
		panic(err)
	}
	half := len(derived) / 2
	signing, encryption := derived[:half], derived[half:]

	tok, err := Cryptography.NewToken(derived)
	hmacOk := false
	if err == nil {
		_, derr := tok.Decrypt(token)
		hmacOk = derr == nil
	}

	var ratchets [][]byte
	if ratchetPriv != nil {
		ratchets = [][]byte{ratchetPriv}
	}
	plaintext, _ := id.Decrypt(payload, ratchets, false)

	printHeader(p, raw)
	f("ephemeral_public", hx(ephemeral))
	f("iv", hx(iv))
	f("ciphertext", hx(ct))
	f("hmac", hx(mac))
	f("identity_hash", hx(id.Hash))
	f("ratchet_public", hx(ratchetPub))
	f("shared_key", hx(shared))
	f("signing_key", hx(signing))
	f("encryption_key", hx(encryption))
	if hmacOk {
		f("hmac_valid", "yes")
	} else {
		f("hmac_valid", "no")
	}
	if plaintext == nil {
		f("plaintext_length", "-")
		f("plaintext", "-")
	} else {
		f("plaintext_length", fmt.Sprintf("%d", len(plaintext)))
		if len(plaintext) == 0 {
			f("plaintext", "-")
		} else {
			f("plaintext", hx(plaintext))
		}
	}
}

const (
	ecPubSize  = 64
	signalSize = 3

	// rns/link.go:66, the only mode it enables.
	linkDefaultMode = 1
)

// LinkValidateRequest is the only exported way into the link id
// derivation: linkIDFromLinkRequestPacket is unexported. It wants a
// destination to own the link, and the link id does not depend on one,
// so any identity serves. Everything the harness then reads off the
// returned Link was computed by rns.
func validateRequest(raw []byte) (*rns.Packet, *rns.Link) {
	p := &rns.Packet{Raw: raw}
	if !p.Unpack() {
		return nil, nil
	}
	id, err := rns.NewIdentity()
	if err != nil {
		panic(err)
	}
	owner, err := rns.NewDestination(id, rns.DestinationIN, rns.DestinationSINGLE, "conformance", "link")
	if err != nil {
		panic(err)
	}
	return p, rns.LinkValidateRequest(owner, p.Data, p)
}

func linkrequest(b [][]byte) {
	raw := b[0]
	if len(raw) < 2 {
		invalid("short-header", [2]interface{}{"length", len(raw)}, [2]interface{}{"minimum_length", 2})
		return
	}

	p, link := validateRequest(raw)
	if p == nil {
		invalid("short-header", [2]interface{}{"length", len(raw)}, [2]interface{}{"minimum_length", headerMinimum(raw)})
		return
	}
	if link == nil {
		invalid("invalid-length",
			[2]interface{}{"payload_length", len(p.Data)},
			[2]interface{}{"accepted_length", ecPubSize},
			[2]interface{}{"signalled_length", ecPubSize + signalSize})
		return
	}

	signalled := len(p.Data) == ecPubSize+signalSize
	printHeader(p, raw)
	f("x25519_public", hx(p.Data[:ecPubSize/2]))
	f("ed25519_public", hx(p.Data[ecPubSize/2:ecPubSize]))
	if signalled {
		f("signalling", hx(p.Data[ecPubSize:]))
	} else {
		f("signalling", "-")
	}
	printMode(link.Mode)
	if signalled {
		f("mtu", fmt.Sprintf("%d", link.MTU))
	} else {
		f("mtu", "-")
	}
	f("link_id", hx(link.LinkID))
}

func linkproof(b [][]byte) {
	requestRaw, identityPublic, raw := b[0], b[1], b[2]

	f("link_request", hx(requestRaw))
	f("signer_public", hx(identityPublic))

	if len(raw) < 2 {
		invalid("short-header", [2]interface{}{"length", len(raw)}, [2]interface{}{"minimum_length", 2})
		return
	}
	p := &rns.Packet{Raw: raw}
	if !p.Unpack() {
		invalid("short-header", [2]interface{}{"length", len(raw)}, [2]interface{}{"minimum_length", headerMinimum(raw)})
		return
	}

	_, requestLink := validateRequest(requestRaw)
	if requestLink == nil {
		panic("the link request does not validate")
	}
	linkID := requestLink.LinkID

	accepted := sigLen + ecPubSize/2
	signalled := len(p.Data) == accepted+signalSize
	if len(p.Data) != accepted && !signalled {
		invalid("invalid-length",
			[2]interface{}{"payload_length", len(p.Data)},
			[2]interface{}{"accepted_length", accepted},
			[2]interface{}{"signalled_length", accepted + signalSize})
		return
	}

	sig := p.Data[:sigLen]
	x25519Public := p.Data[sigLen : sigLen+ecPubSize/2]
	signalling := p.Data[sigLen+ecPubSize/2:]

	signer := &rns.Identity{}
	if err := signer.LoadPublicKey(identityPublic); err != nil {
		panic(err)
	}
	signerEd := identityPublic[ecPubSize/2:]

	// Follows rns/link.go:2033. validateProof drives a state machine and
	// returns nothing, so the material is assembled here and handed to
	// rns's own Identity.Validate.
	signed := append([]byte{}, linkID...)
	signed = append(signed, x25519Public...)
	signed = append(signed, signerEd...)
	signed = append(signed, signalling...)

	printHeader(p, raw)
	f("link_id", hx(linkID))
	f("link_id_match", yesNo(bytes.Equal(p.DestinationHash, linkID)))
	f("signature", hx(sig))
	f("x25519_public", hx(x25519Public))
	// linkModeFromProofPacket and linkMTUFromProofPacket are rns's own,
	// at rns/link.go:2798 and rns/link.go:2755, and both are unexported.
	// They are followed here rather than called.
	if signalled {
		f("signalling", hx(signalling))
		printMode(int(signalling[0]&0xe0) >> 5)
		f("mtu", fmt.Sprintf("%d", (int(signalling[0])<<16|int(signalling[1])<<8|int(signalling[2]))&0x1fffff))
	} else {
		f("signalling", "-")
		printMode(linkDefaultMode)
		f("mtu", "-")
	}
	f("signer_ed25519", hx(signerEd))
	f("signed_data", hx(signed))
	f("signature_valid", yesNo(signer.Validate(sig, signed)))
}

func linkdata(b [][]byte) {
	requestRaw, responderPrivate, raw := b[0], b[1], b[2]

	f("link_request", hx(requestRaw))
	f("responder_private", hx(responderPrivate))

	if len(raw) < 2 {
		invalid("short-header", [2]interface{}{"length", len(raw)}, [2]interface{}{"minimum_length", 2})
		return
	}
	p := &rns.Packet{Raw: raw}
	if !p.Unpack() {
		invalid("short-header", [2]interface{}{"length", len(raw)}, [2]interface{}{"minimum_length", headerMinimum(raw)})
		return
	}

	request, requestLink := validateRequest(requestRaw)
	if request == nil {
		panic("the link request does not decode")
	}

	// LinkValidateRequest sets the link id and then runs the handshake,
	// and it returns nil for the whole link when the handshake fails.
	// The id it had already computed goes with it, so go-reticulum
	// states none where the reference reads one out of the request
	// bytes alone. doc/harness rule 6: what it produced nothing for is
	// "-", and the fields after it still stand.
	agreed := requestLink != nil
	var linkID []byte
	if agreed {
		linkID = requestLink.LinkID
	}

	printHeader(p, raw)
	if agreed {
		f("link_id", hx(linkID))
		f("link_id_match", yesNo(bytes.Equal(p.DestinationHash, linkID)))
	} else {
		f("link_id", "-")
		f("link_id_match", "-")
	}

	// A resource part is not encrypted by the packet layer: the
	// resource encrypted the whole stream through the link and cut the
	// token into parts. rns/packet.go:PacketCtxResource.
	if p.Context == rns.PacketCtxResource || p.Context == 0xfa {
		f("encrypted", "no")
		f("plaintext_length", fmt.Sprintf("%d", len(p.Data)))
		if len(p.Data) > 0 {
			f("plaintext", hx(p.Data))
		} else {
			f("plaintext", "-")
		}
		return
	}
	f("encrypted", "yes")

	// Cutting the token into iv, ciphertext and hmac is transcription:
	// go-reticulum decrypts behind Token.Decrypt and exposes none of the
	// three. A payload shorter than an iv and an hmac has no token to
	// cut, and this took the length for granted and sliced out of range,
	// which the recover at the top turned into one error line in place
	// of every field. doc/harness rule 6: print what there is and "-"
	// for what there is not. The length rule is not supplied here; that
	// go-reticulum reports none is the result.
	var iv, ct, mac []byte
	haveToken := len(p.Data) >= 48
	if haveToken {
		iv = p.Data[:16]
		ct = p.Data[16 : len(p.Data)-32]
		mac = p.Data[len(p.Data)-32:]
	}

	// The agreement already failed inside LinkValidateRequest above, so
	// there is no link key and nothing after it to derive. The token is
	// on the wire either way and is printed.
	if !agreed {
		f("iv", hx(iv))
		f("ciphertext", hx(ct))
		f("hmac", hx(mac))
		for _, n := range []string{"shared_key", "signing_key", "encryption_key",
			"hmac_valid", "plaintext_length", "plaintext"} {
			f(n, "-")
		}
		return
	}

	// The link keeps its private key unexported, so the agreement uses
	// Go's own curve, which is what rns uses internally.
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(responderPrivate)
	if err != nil {
		panic(err)
	}
	peer, err := curve.NewPublicKey(request.Data[:ecPubSize/2])
	if err != nil {
		panic(err)
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		panic(err)
	}

	// The derived length is 64 for AES_256_CBC, the only mode rns
	// enables at rns/link.go:72. The salt is the link id and the
	// context empty, as rns/link.go does.
	derived, err := Cryptography.HKDF(64, shared, linkID, nil)
	if err != nil {
		panic(err)
	}
	signing, encryption := derived[:32], derived[32:]

	// verifyHMAC is unexported; Decrypt refuses a token whose HMAC does
	// not verify, so its verdict stands in for both.
	token, terr := Cryptography.NewToken(derived)
	var plaintext []byte
	macOK := false
	if terr == nil {
		var derr error
		plaintext, derr = token.Decrypt(p.Data)
		macOK = derr == nil
		if derr != nil {
			plaintext = nil
		}
	}

	f("iv", hx(iv))
	f("ciphertext", hx(ct))
	f("hmac", hx(mac))
	f("shared_key", hx(shared))
	f("signing_key", hx(signing))
	f("encryption_key", hx(encryption))
	f("hmac_valid", yesNo(macOK))
	if plaintext == nil {
		f("plaintext_length", "-")
		f("plaintext", "-")
		return
	}
	f("plaintext_length", fmt.Sprintf("%d", len(plaintext)))
	if len(plaintext) > 0 {
		f("plaintext", hx(plaintext))
	} else {
		f("plaintext", "-")
	}

	// The channel envelope. go-reticulum has Envelope.Unpack at
	// rns/channel.go:108, and both it and the raw field it reads are
	// unexported, so this follows those three lines with the same
	// offsets rather than calling them.
	if p.Context == 0x0e && len(plaintext) >= 6 {
		f("msgtype", hx(plaintext[0:2]))
		f("sequence", fmt.Sprintf("%d", binary.BigEndian.Uint16(plaintext[2:4])))
		f("declared_length", fmt.Sprintf("%d", binary.BigEndian.Uint16(plaintext[4:6])))
		if len(plaintext) > 6 {
			f("message", hx(plaintext[6:]))
		} else {
			f("message", "-")
		}
	}

	// go-reticulum's own msgpack, as link.go:1543 reads a request and
	// link.go:1562 a response. The time comes back as a float64 and is
	// printed as the eight bytes it was decoded from.
	// go-reticulum's own advertisement decoder, rns/resource.go:2097.
	// It has no parser for the part request, the hashmap update or a
	// cancel: rns/resource.go reads those inline in the transfer loop
	// and yields nothing.
	if p.Context == rns.PacketCtxResourceAdv {
		adv, err := rns.ResourceAdvertisement{}.Unpack(plaintext)
		if err != nil {
			panic(err)
		}
		f("transfer_size", fmt.Sprintf("%d", adv.T))
		f("data_size", fmt.Sprintf("%d", adv.D))
		f("resource_parts", fmt.Sprintf("%d", adv.N))
		f("resource_hash", hx(adv.H))
		f("resource_random", hx(adv.R))
		f("original_hash", hx(adv.O))
		f("segment_index", fmt.Sprintf("%d", adv.I))
		f("total_segments", fmt.Sprintf("%d", adv.L))
		f("request_id", hx(adv.Q))
		f("resource_flags", fmt.Sprintf("%02x", adv.F))
		f("hashmap", hx(adv.M))
	}
	if p.Context == rns.PacketCtxResourceReq {
		f("hashmap_exhausted", "-")
		f("last_map_hash", "-")
		f("resource_hash", "-")
		f("requested_hashes", "-")
	}
	if p.Context == rns.PacketCtxResourceHMU {
		f("resource_hash", "-")
		f("segment_index", "-")
		f("hashmap", "-")
	}
	if p.Context == rns.PacketCtxResourceICL || p.Context == rns.PacketCtxResourceRCL {
		f("resource_hash", "-")
	}

	if p.Context == rns.PacketCtxRequest || p.Context == rns.PacketCtxResponse {
		var unpacked []any
		if err := umsgpack.Unpackb(plaintext, &unpacked); err != nil {
			panic(err)
		}
		if p.Context == rns.PacketCtxRequest {
			at := make([]byte, 8)
			binary.BigEndian.PutUint64(at, math.Float64bits(unpacked[0].(float64)))
			f("request_time", hx(at))
			f("request_path_hash", mpBin(unpacked[1]))
			f("request_data", mpBin(unpacked[2]))
		} else {
			f("request_id", mpBin(unpacked[0]))
			f("response_data", mpBin(unpacked[1]))
		}
	}

	if p.Context == 0xfb && len(plaintext) == keySize+sigLen {
		pub := plaintext[:keySize]
		sig := plaintext[keySize:]
		signed := append(append([]byte{}, linkID...), pub...)
		id := &rns.Identity{}
		if err := id.LoadPublicKey(pub); err != nil {
			panic(err)
		}
		f("identity_public", hx(pub))
		f("identity_hash", hx(rns.TruncatedHash(pub)))
		f("identity_signed", hx(signed))
		f("identity_valid", yesNo(id.Validate(sig, signed)))
	}
}

func printMode(mode int) {
	if mode == 1 {
		f("mode", "aes256_cbc")
	} else {
		f("mode", fmt.Sprintf("%02x", mode))
	}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: goret kind rawfile")
		os.Exit(2)
	}
	kind, path := os.Args[1], os.Args[2]

	// rns.Log writes through fmt.Println, so anything the library logs
	// at or below Loglevel lands in the field stream. os.Stdout is read
	// at each call, so pointing it at standard error moves the log and
	// leaves the fields, which are written to the handle saved here.
	// cmd/check reads only standard output. doc/harness rule 6.
	stdout := os.Stdout
	os.Stdout = os.Stderr

	defer func() {
		if r := recover(); r != nil {
			line := strings.SplitN(fmt.Sprintf("%v", r), "\n", 2)[0]
			fmt.Fprintf(stdout, "%-*s %s\n", W, "error", line)
		}
	}()

	blobs := readRaw(path)
	switch kind {
	case "identity":
		identity(blobs)
	case "keyset":
		keyset(blobs)
	case "destination":
		destination(blobs)
	case "signature":
		signature(blobs)
	case "sign":
		sign(blobs)
	case "announce":
		announce(blobs)
	case "encrypted":
		encrypted(blobs)
	case "linkrequest":
		linkrequest(blobs)
	case "linkproof":
		linkproof(blobs)
	case "linkdata":
		linkdata(blobs)
	case "proof":
		proof(blobs)
	default:
		// 77 says the kind is not implemented here. cmd/check counts
		// it as skipped rather than failed; see ../README.
		fmt.Fprintln(os.Stderr, "kind not implemented: "+kind)
		os.Exit(77)
	}
	fmt.Fprint(stdout, strings.Join(out, "\n")+"\n")
}
