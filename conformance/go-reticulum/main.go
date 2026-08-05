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
	"os"
	"strings"

	"crypto/ecdh"

	"github.com/svanichkin/go-reticulum/rns"
	Cryptography "github.com/svanichkin/go-reticulum/rns/cryptography"
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

var out []string

func f(name, value string) { out = append(out, fmt.Sprintf("%-*s %s", W, name, value)) }

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
	f("public_key", hex.EncodeToString(pub))
	f("x25519_public", hex.EncodeToString(pub[:32]))
	f("ed25519_public", hex.EncodeToString(pub[32:]))
	f("identity_hash", hex.EncodeToString(id.Hash))
}

func keyset(b [][]byte) {
	id, err := rns.IdentityFromBytes(b[0])
	if err != nil {
		panic(err)
	}
	prv, pub := id.GetPrivateKey(), id.GetPublicKey()
	f("private_key", hex.EncodeToString(prv))
	f("x25519_private", hex.EncodeToString(prv[:32]))
	f("ed25519_private", hex.EncodeToString(prv[32:]))
	f("public_key", hex.EncodeToString(pub))
	f("x25519_public", hex.EncodeToString(pub[:32]))
	f("ed25519_public", hex.EncodeToString(pub[32:]))
	f("identity_hash", hex.EncodeToString(id.Hash))
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

	f("name", hex.EncodeToString(b[0]))
	f("app_name", hex.EncodeToString([]byte(appName)))
	for _, a := range aspects {
		f("aspect", hex.EncodeToString([]byte(a)))
	}
	f("name_hash", hex.EncodeToString(nameHash))
	if b[1] == nil {
		f("identity_hash", "-")
	} else {
		f("identity_hash", hex.EncodeToString(b[1]))
	}
	f("destination_hash", hex.EncodeToString(dh))
}

func signature(b [][]byte) {
	id := &rns.Identity{}
	if err := id.LoadPublicKey(b[0]); err != nil {
		panic(err)
	}
	digest := sha256.Sum256(b[1])
	f("ed25519_public", hex.EncodeToString(b[0][32:]))
	f("message_length", fmt.Sprintf("%d", len(b[1])))
	f("message_sha256", hex.EncodeToString(digest[:]))
	f("signature", hex.EncodeToString(b[2]))
	if id.Validate(b[2], b[1]) {
		f("valid", "yes")
	} else {
		f("valid", "no")
	}
}

var destTypes = []string{"single", "group", "plain", "link"}
var packetTypes = []string{"data", "announce", "linkrequest", "proof"}
var xportTypes = []string{"broadcast", "transport", "relay", "tunnel"}

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
		invalid("short-header", [2]interface{}{"length", len(raw)}, [2]interface{}{"minimum_length", 19})
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
		f("transport_id", hex.EncodeToString(p.TransportID))
	} else {
		f("transport_id", "-")
	}
	f("destination_hash", hex.EncodeToString(p.DestinationHash))
	switch p.Context {
	case 0x00:
		f("context", "none")
	case 0x0b:
		f("context", "path_response")
	default:
		f("context", fmt.Sprintf("%02x", p.Context))
	}
	f("payload_length", fmt.Sprintf("%d", len(payload)))
	f("public_key", hex.EncodeToString(publicKey))
	f("name_hash", hex.EncodeToString(nameHash))
	f("random_hash", hex.EncodeToString(randomHash))
	if ratchet != nil {
		f("ratchet", hex.EncodeToString(ratchet))
	} else {
		f("ratchet", "-")
	}
	f("signature", hex.EncodeToString(sig))
	if len(appData) > 0 {
		f("app_data", hex.EncodeToString(appData))
	} else {
		f("app_data", "-")
	}
	f("identity_hash", hex.EncodeToString(announced.Hash))
	f("expected_hash", hex.EncodeToString(expected))
	if bytes.Equal(p.DestinationHash, expected) {
		f("destination_match", "yes")
	} else {
		f("destination_match", "no")
	}
	f("signed_data", hex.EncodeToString(signed))
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
		f("transport_id", hex.EncodeToString(p.TransportID))
	} else {
		f("transport_id", "-")
	}
	f("destination_hash", hex.EncodeToString(p.DestinationHash))
	f("context", contextName(p.Context))
	f("payload_length", fmt.Sprintf("%d", len(p.Data)))
}

// Named from rns's own context constants at rns/packet.go:36-49.
func contextName(c byte) string {
	switch c {
	case rns.PacketCtxNone:
		return "none"
	case rns.PacketCtxPathResponse:
		return "path_response"
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

	if len(raw) < 2 {
		invalid("short-header", [2]interface{}{"length", len(raw)}, [2]interface{}{"minimum_length", 2})
		return
	}
	p := &rns.Packet{Raw: raw}
	if !p.Unpack() {
		invalid("short-header", [2]interface{}{"length", len(raw)}, [2]interface{}{"minimum_length", 19})
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
	shared, err := sk.ECDH(pp)
	if err != nil {
		panic(err)
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
	f("ephemeral_public", hex.EncodeToString(ephemeral))
	f("iv", hex.EncodeToString(iv))
	f("ciphertext", hex.EncodeToString(ct))
	f("hmac", hex.EncodeToString(mac))
	f("identity_hash", hex.EncodeToString(id.Hash))
	if ratchetPub == nil {
		f("ratchet_public", "-")
	} else {
		f("ratchet_public", hex.EncodeToString(ratchetPub))
	}
	f("shared_key", hex.EncodeToString(shared))
	f("signing_key", hex.EncodeToString(signing))
	f("encryption_key", hex.EncodeToString(encryption))
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
			f("plaintext", hex.EncodeToString(plaintext))
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
		invalid("short-header", [2]interface{}{"length", len(raw)}, [2]interface{}{"minimum_length", 19})
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
	f("x25519_public", hex.EncodeToString(p.Data[:ecPubSize/2]))
	f("ed25519_public", hex.EncodeToString(p.Data[ecPubSize/2:ecPubSize]))
	if signalled {
		f("signalling", hex.EncodeToString(p.Data[ecPubSize:]))
	} else {
		f("signalling", "-")
	}
	printMode(link.Mode)
	if signalled {
		f("mtu", fmt.Sprintf("%d", link.MTU))
	} else {
		f("mtu", "-")
	}
	f("link_id", hex.EncodeToString(link.LinkID))
}

func linkproof(b [][]byte) {
	requestRaw, identityPublic, raw := b[0], b[1], b[2]

	if len(raw) < 2 {
		invalid("short-header", [2]interface{}{"length", len(raw)}, [2]interface{}{"minimum_length", 2})
		return
	}
	p := &rns.Packet{Raw: raw}
	if !p.Unpack() {
		invalid("short-header", [2]interface{}{"length", len(raw)}, [2]interface{}{"minimum_length", 19})
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
	f("link_id", hex.EncodeToString(linkID))
	f("link_id_match", yesNo(bytes.Equal(p.DestinationHash, linkID)))
	f("signature", hex.EncodeToString(sig))
	f("x25519_public", hex.EncodeToString(x25519Public))
	// linkModeFromProofPacket and linkMTUFromProofPacket are rns's own,
	// at rns/link.go:2798 and rns/link.go:2755, and both are unexported.
	// They are followed here rather than called.
	if signalled {
		f("signalling", hex.EncodeToString(signalling))
		printMode(int(signalling[0]&0xe0) >> 5)
		f("mtu", fmt.Sprintf("%d", (int(signalling[0])<<16|int(signalling[1])<<8|int(signalling[2]))&0x1fffff))
	} else {
		f("signalling", "-")
		printMode(linkDefaultMode)
		f("mtu", "-")
	}
	f("signer_ed25519", hex.EncodeToString(signerEd))
	f("signed_data", hex.EncodeToString(signed))
	f("signature_valid", yesNo(signer.Validate(sig, signed)))
}

func linkdata(b [][]byte) {
	requestRaw, responderPrivate, raw := b[0], b[1], b[2]

	if len(raw) < 2 {
		invalid("short-header", [2]interface{}{"length", len(raw)}, [2]interface{}{"minimum_length", 2})
		return
	}
	p := &rns.Packet{Raw: raw}
	if !p.Unpack() {
		invalid("short-header", [2]interface{}{"length", len(raw)}, [2]interface{}{"minimum_length", 19})
		return
	}

	request, requestLink := validateRequest(requestRaw)
	if requestLink == nil {
		panic("the link request does not validate")
	}
	linkID := requestLink.LinkID

	printHeader(p, raw)
	f("link_id", hex.EncodeToString(linkID))
	f("link_id_match", yesNo(bytes.Equal(p.DestinationHash, linkID)))

	if p.Context == 0xfa {
		f("encrypted", "no")
		f("plaintext_length", fmt.Sprintf("%d", len(p.Data)))
		if len(p.Data) > 0 {
			f("plaintext", hex.EncodeToString(p.Data))
		} else {
			f("plaintext", "-")
		}
		return
	}
	f("encrypted", "yes")

	iv := p.Data[:16]
	ct := p.Data[16 : len(p.Data)-32]
	mac := p.Data[len(p.Data)-32:]

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

	f("iv", hex.EncodeToString(iv))
	f("ciphertext", hex.EncodeToString(ct))
	f("hmac", hex.EncodeToString(mac))
	f("shared_key", hex.EncodeToString(shared))
	f("signing_key", hex.EncodeToString(signing))
	f("encryption_key", hex.EncodeToString(encryption))
	f("hmac_valid", yesNo(macOK))
	if plaintext == nil {
		f("plaintext_length", "-")
		f("plaintext", "-")
		return
	}
	f("plaintext_length", fmt.Sprintf("%d", len(plaintext)))
	if len(plaintext) > 0 {
		f("plaintext", hex.EncodeToString(plaintext))
	} else {
		f("plaintext", "-")
	}

	if p.Context == 0xfb && len(plaintext) == keySize+sigLen {
		pub := plaintext[:keySize]
		sig := plaintext[keySize:]
		signed := append(append([]byte{}, linkID...), pub...)
		id := &rns.Identity{}
		if err := id.LoadPublicKey(pub); err != nil {
			panic(err)
		}
		f("identity_public", hex.EncodeToString(pub))
		f("identity_hash", hex.EncodeToString(rns.TruncatedHash(pub)))
		f("identity_signed", hex.EncodeToString(signed))
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

	defer func() {
		if r := recover(); r != nil {
			line := strings.SplitN(fmt.Sprintf("%v", r), "\n", 2)[0]
			fmt.Printf("%-*s %s\n", W, "error", line)
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
	default:
		fmt.Fprintln(os.Stderr, "unknown kind "+kind)
		os.Exit(2)
	}
	fmt.Print(strings.Join(out, "\n") + "\n")
}
