// Conformance harness for Quad4-Software/Reticulum-Go.
//
//	q4ret kind rawfile
//
// See ../README for what a harness may and may not do.
//
// Reticulum-Go exports more of its own machinery than the six
// implementations measured before it: the X25519 agreement, both HKDF
// derivations, the AES and HMAC primitives, the link id, the resource
// advertisement decoder and the whole interface access code are
// exported and called here. What is still followed rather than called
// is marked at the place, as ../../doc/harness requires.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"strings"

	"quad4/msgpack/v5/pkg/msgpack"
	"quad4/reticulum-go/pkg/cryptography"
	"quad4/reticulum-go/pkg/destination"
	"quad4/reticulum-go/pkg/identity"
	"quad4/reticulum-go/pkg/ifac"
	"quad4/reticulum-go/pkg/packet"
	"quad4/reticulum-go/pkg/resource"
)

const (
	W = 18

	keySize  = 64
	nameLen  = 10
	randLen  = 10
	sigLen   = 64
	ratchLen = 32
	addrLen  = 16
)

var out []string

func f(name, value string) { out = append(out, fmt.Sprintf("%-*s %s", W, name, value)) }

func d(n int) string { return fmt.Sprintf("%d", n) }

// An empty byte string prints as "-", as cmd/dump's field_hex does.
// Hex cannot spell it, and a name followed by nothing cannot be told
// from a truncated line.
func hx(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return hex.EncodeToString(b)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
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

func invalid(reason string, pairs ...[2]any) {
	f("invalid", reason)
	for _, kv := range pairs {
		f(kv[0].(string), fmt.Sprintf("%d", kv[1]))
	}
}

func num(name string, v int) [2]any { return [2]any{name, v} }

// ---------------------------------------------------------------- identity

func doIdentity(b [][]byte) {
	id := identity.FromPublicKey(b[0])
	if id == nil {
		panic("public key refused")
	}
	pub := id.GetPublicKey()
	f("public_key", hx(pub))
	f("x25519_public", hx(pub[:32]))
	f("ed25519_public", hx(pub[32:]))
	f("identity_hash", hx(id.Hash()))
}

func doKeyset(b [][]byte) {
	id, err := identity.FromBytes(b[0])
	if err != nil {
		panic(err)
	}
	prv, err := id.GetPrivateKey()
	if err != nil {
		panic(err)
	}
	pub := id.GetPublicKey()
	f("private_key", hx(prv))
	f("x25519_private", hx(prv[:32]))
	f("ed25519_private", hx(prv[32:]))
	f("public_key", hx(pub))
	f("x25519_public", hx(pub[:32]))
	f("ed25519_public", hx(pub[32:]))
	f("identity_hash", hx(id.Hash()))
}

// ------------------------------------------------------------- destination

func doDestination(b [][]byte) {
	name := string(b[0])
	parts := strings.Split(name, ".")
	appName, aspects := parts[0], parts[1:]

	expanded := destination.ExpandAppName(appName, aspects...)
	nameHash := cryptography.Hash([]byte(expanded))[:nameLen]

	// destination.Hash takes an *identity.Identity and derives the
	// identity hash from its public key, which the vector does not
	// carry; only the hash is on file. The two remaining lines of
	// destination.go:227 Hash are followed here with its own hash
	// function. With no identity there is nothing to follow and
	// destination.Hash is called.
	var destHash []byte
	if b[1] == nil {
		destHash = destination.Hash(nil, appName, aspects...)
	} else {
		combined := append(append([]byte{}, nameHash...), b[1]...)
		destHash = cryptography.Hash(combined)[:addrLen]
	}

	f("name", hx(b[0]))
	f("app_name", hx([]byte(appName)))
	for _, a := range aspects {
		f("aspect", hx([]byte(a)))
	}
	f("name_hash", hx(nameHash))
	f("identity_hash", hx(b[1]))
	f("destination_hash", hx(destHash))
}

// --------------------------------------------------------------- signature

func doSignature(b [][]byte) {
	id := identity.FromPublicKey(b[0])
	if id == nil {
		panic("public key refused")
	}
	digest := sha256.Sum256(b[1])
	f("ed25519_public", hx(b[0][32:]))
	f("message_length", d(len(b[1])))
	f("message_sha256", hx(digest[:]))
	f("signature", hx(b[2]))
	f("valid", yesNo(id.Verify(b[1], b[2])))
}

// The other direction of signature: the signature is produced, not
// handed in. identity.go:107 Sign.
func doSign(b [][]byte) {
	id, err := identity.FromBytes(b[0])
	if err != nil {
		panic(err)
	}
	sig, err := id.Sign(b[1])
	if err != nil {
		panic(err)
	}
	prv, err := id.GetPrivateKey()
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(b[1])
	f("private_key", hx(prv))
	f("ed25519_private", hx(prv[32:]))
	f("ed25519_public", hx(id.GetPublicKey()[32:]))
	f("message_length", d(len(b[1])))
	f("message_sha256", hx(digest[:]))
	f("signature", hx(sig))
}

// ------------------------------------------------------------------ header

var destTypes = []string{"single", "group", "plain", "link"}
var packetTypes = []string{"data", "announce", "linkrequest", "proof"}
var xportTypes = []string{"broadcast", "transport", "relay", "tunnel"}

// unpack runs packet.Unpack and turns its refusals into the rejection
// the corpus names. The thresholds are Reticulum-Go's own, from
// pkg/packet/packet.go:219: MinPacketSize for a frame too short to
// hold a header type, and the header length for one too short to hold
// a header. The hop limit is checked there too, which is the one
// rejection none of the six earlier implementations has; PathfinderM
// is its own constant.
func unpack(raw []byte) *packet.Packet {
	p := &packet.Packet{Raw: raw}
	if err := p.Unpack(); err != nil {
		switch {
		case len(raw) >= 2 && int(raw[1]) >= packet.PathfinderM:
			invalid("hop-limit", num("hops", int(raw[1])), num("hop_limit", packet.PathfinderM))
		case len(raw) < packet.MinPacketSize:
			invalid("short-header", num("length", len(raw)),
				num("minimum_length", packet.MinPacketSize))
		default:
			min := packet.TruncatedHashLength + packet.MinPacketSize
			if (raw[0]&packet.HeaderMaskHeaderType)>>6 == packet.HeaderType2 {
				min = 2*packet.TruncatedHashLength + packet.MinPacketSize
			}
			invalid("short-header", num("length", len(raw)), num("minimum_length", min))
		}
		return nil
	}
	return p
}

// Named from Reticulum-Go's own context constants at
// pkg/packet/constants.go.
func contextName(c byte) string {
	switch c {
	case packet.ContextNone:
		return "none"
	case packet.ContextResource:
		return "resource"
	case packet.ContextResourceAdv:
		return "resource_adv"
	case packet.ContextResourceReq:
		return "resource_req"
	case packet.ContextResourceHMU:
		return "resource_hmu"
	case packet.ContextResourcePRF:
		return "resource_prf"
	case packet.ContextResourceICL:
		return "resource_icl"
	case packet.ContextResourceRCL:
		return "resource_rcl"
	case packet.ContextRequest:
		return "request"
	case packet.ContextResponse:
		return "response"
	case packet.ContextPathResponse:
		return "path_response"
	case packet.ContextChannel:
		return "channel"
	case packet.ContextKeepalive:
		return "keepalive"
	case packet.ContextLinkIdentify:
		return "link_identify"
	case packet.ContextLinkClose:
		return "link_close"
	case packet.ContextLinkProof:
		return "link_proof"
	case packet.ContextLRRTT:
		return "link_rtt"
	case packet.ContextLRProof:
		return "link_request_proof"
	}
	return fmt.Sprintf("%02x", c)
}

// Reticulum-Go exposes no entry point that yields the header fields on
// their own; Packet.Unpack fills the struct and every field below is
// read off it.
func printHeader(p *packet.Packet, raw []byte) {
	f("flags", fmt.Sprintf("%02x", raw[0]))
	f("header_type", d(int(p.HeaderType)+1))
	if p.ContextFlag == packet.FlagSet {
		f("context_flag", "set")
	} else {
		f("context_flag", "unset")
	}
	f("transport_type", xportTypes[p.TransportType])
	f("destination_type", destTypes[p.DestinationType])
	f("packet_type", packetTypes[p.PacketType])
	f("hops", d(int(p.Hops)))
	f("transport_id", hx(p.TransportID))
	f("destination_hash", hx(p.DestinationHash))
	f("context", contextName(p.Context))
	f("payload_length", d(len(p.Data)))
}

// ---------------------------------------------------------------- announce

func doAnnounce(b [][]byte) {
	raw := b[0]
	p := unpack(raw)
	if p == nil {
		return
	}

	payload := p.Data
	min := keySize + nameLen + randLen + sigLen
	if p.ContextFlag == packet.FlagSet {
		min += ratchLen
	}
	if len(payload) < min {
		invalid("short-payload", num("payload_length", len(payload)),
			num("minimum_length", min))
		return
	}

	// Follows pkg/announce/announce.go:150 HandleAnnounce, which is
	// the only entry point into the announce fields and returns only
	// an error.
	at := 0
	publicKey := payload[at : at+keySize]
	at += keySize
	nameHash := payload[at : at+nameLen]
	at += nameLen
	randomHash := payload[at : at+randLen]
	at += randLen
	var ratchet []byte
	if p.ContextFlag == packet.FlagSet {
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

	announced := identity.FromPublicKey(publicKey)
	if announced == nil {
		panic("announced public key refused")
	}
	// The second half of destination.go:227 Hash again; see
	// doDestination.
	expected := cryptography.Hash(append(append([]byte{}, nameHash...), announced.Hash()...))[:addrLen]

	printHeader(p, raw)
	f("public_key", hx(publicKey))
	f("name_hash", hx(nameHash))
	f("random_hash", hx(randomHash))
	f("ratchet", hx(ratchet))
	f("signature", hx(sig))
	f("app_data", hx(appData))
	f("identity_hash", hx(announced.Hash()))
	f("expected_hash", hx(expected))
	f("destination_match", yesNo(bytes.Equal(p.DestinationHash, expected)))
	f("signed_data", hx(signed))
	f("signature_valid", yesNo(announced.Verify(signed, sig)))
}

// ------------------------------------------------------------------- proof

func doProof(b [][]byte) {
	provedRaw, signerPublic, raw := b[0], b[1], b[2]

	f("proved_packet", hx(provedRaw))
	f("signer_public", hx(signerPublic))

	proved := &packet.Packet{Raw: provedRaw}
	if err := proved.Unpack(); err != nil {
		panic("the proved packet does not decode: " + err.Error())
	}
	p := unpack(raw)
	if p == nil {
		return
	}
	printHeader(p, raw)

	payload := p.Data
	explicit := len(payload) == 32+sigLen
	packetHash := proved.GetHash()
	signature := payload
	if explicit {
		signature = payload[32:]
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
	// under one Ed25519 public key. PacketReceipt.ValidateLinkProof
	// (pkg/packet/receipt.go:128) wants a live Link to reach the peer
	// key through, so the key goes to Reticulum-Go's own verifier
	// instead, which is what validateLinkSignature ends at.
	if p.DestinationType == packet.DestinationLink {
		f("link_id", hx(proved.DestinationHash))
		f("link_id_match", yesNo(bytes.Equal(p.DestinationHash, proved.DestinationHash)))
		f("signature", hx(signature))
		f("signer_ed25519", hx(signerPublic))
		f("signature_valid", yesNo(cryptography.Verify(signerPublic, packetHash, signature)))
		return
	}

	// To a destination the whole proof is validated by
	// PacketReceipt.ValidateProof, which is exported and called.
	receipt := packet.NewPacketReceipt(proved)
	if len(signerPublic) == keySize {
		receipt.SetDestinationIdentity(identity.FromPublicKey(signerPublic))
	}

	f("proof_destination", hx(packetHash[:addrLen]))
	f("destination_match", yesNo(bytes.Equal(p.DestinationHash, packetHash[:addrLen])))
	f("signature", hx(signature))
	f("signer_ed25519", hx(signerPublic[32:]))
	f("signature_valid", yesNo(receipt.ValidateProof(payload, p)))
}

// --------------------------------------------------------------- encrypted

func doEncrypted(b [][]byte) {
	priv, ratchetPriv, raw := b[0], b[1], b[2]

	// Echoes of the input lines, so that expect holds every byte of
	// raw. Not a claim about Reticulum-Go: the harness was handed
	// these.
	f("recipient_private", hx(priv))
	f("ratchet_private", hx(ratchetPriv))

	p := unpack(raw)
	if p == nil {
		return
	}

	payload := p.Data
	min := 32 + 48
	if len(payload) < min {
		invalid("short-payload", num("payload_length", len(payload)),
			num("minimum_length", min))
		return
	}

	ephemeral := payload[:32]
	token := payload[32:]
	iv := token[:16]
	ct := token[16 : len(token)-32]
	mac := token[len(token)-32:]

	id, err := identity.FromBytes(priv)
	if err != nil {
		panic(err)
	}

	agree := priv[:32]
	var ratchetPub []byte
	if ratchetPriv != nil {
		agree = ratchetPriv
		ratchetPub, err = cryptography.PublicKeyFromPrivate(ratchetPriv)
		if err != nil {
			panic(err)
		}
	}

	printHeader(p, raw)
	f("ephemeral_public", hx(ephemeral))
	f("iv", hx(iv))
	f("ciphertext", hx(ct))
	f("hmac", hx(mac))
	f("identity_hash", hx(id.Hash()))
	f("ratchet_public", hx(ratchetPub))

	// A refused agreement is a result, not a harness error. The curve
	// behind cryptography.DeriveSharedSecret refuses a point of small
	// order rather than returning the all-zero secret, which is what
	// the pinned backend does, and everything after the agreement is
	// then unreachable rather than wrong.
	shared, err := cryptography.DeriveSharedSecret(agree, ephemeral)
	if err != nil {
		for _, n := range []string{"shared_key", "signing_key", "encryption_key",
			"hmac_valid", "plaintext_length", "plaintext"} {
			f(n, "-")
		}
		return
	}

	derived, err := cryptography.DeriveIdentityKeyMaterial(shared, id.GetSalt(), id.GetContext())
	if err != nil {
		panic(err)
	}
	signing, encryption := derived[:32], derived[32:]

	// identity.go:445 Decrypt verifies the hmac over the ciphertext
	// alone and refuses the token when it does not match, so its
	// verdict stands in for both. ValidateHMAC is called separately
	// because Decrypt reports one error for either failure.
	hmacOK := cryptography.ValidateHMAC(signing, token[:len(token)-32], mac)

	var ratchets [][]byte
	if ratchetPriv != nil {
		ratchets = [][]byte{ratchetPriv}
	}
	plaintext, _ := id.Decrypt(payload, ratchets, false, nil)

	f("shared_key", hx(shared))
	f("signing_key", hx(signing))
	f("encryption_key", hx(encryption))
	f("hmac_valid", yesNo(hmacOK))
	if plaintext == nil {
		f("plaintext_length", "-")
		f("plaintext", "-")
		return
	}
	f("plaintext_length", d(len(plaintext)))
	f("plaintext", hx(plaintext))
}

// -------------------------------------------------------------------- link

const (
	ecPubSize  = 64
	signalSize = 3

	// pkg/link/constants.go, the only mode ENABLED_MODES enables.
	linkDefaultMode = 1

	// pkg/link/link.go:2283 decryptWithKeys, one aes block for the iv,
	// one for the shortest ciphertext and 32 for the hmac.
	linkTokenMin = 16 + 16 + 32

	// pkg/channel/constants.go:36 ChannelHeaderSize.
	channelHeaderSize = 6

	// pkg/link/constants.go:69 LinkResourceMappedFlag.
	resourceMappedFlag = 0xFF
)

// The link id derivation is exported: packet.LinkIDFromLinkRequest at
// pkg/packet/packet.go:304 truncates the excess over the key size
// before hashing, as the reference does.
func linkID(requestRaw []byte) ([]byte, *packet.Packet) {
	p := &packet.Packet{Raw: requestRaw}
	if err := p.Unpack(); err != nil {
		return nil, nil
	}
	return packet.LinkIDFromLinkRequest(p), p
}

// signallingBytes is Reticulum-Go's own at pkg/link/link.go:3065 and
// unexported; the two readers of it, at link.go:3446 and link.go:3526,
// are inside methods that drive a state machine. Both are followed
// here with the package's own masks.
func printSignalling(signalling []byte) {
	if signalling == nil {
		f("signalling", "-")
		printMode(linkDefaultMode)
		f("mtu", "-")
		return
	}
	f("signalling", hx(signalling))
	printMode(int(signalling[0]&0xE0) >> 5)
	f("mtu", d((int(signalling[0]&0x1F)<<16)|(int(signalling[1])<<8)|int(signalling[2])))
}

func printMode(mode int) {
	if mode == linkDefaultMode {
		f("mode", "aes256_cbc")
	} else {
		f("mode", fmt.Sprintf("%02x", mode))
	}
}

func doLinkRequest(b [][]byte) {
	raw := b[0]
	p := unpack(raw)
	if p == nil {
		return
	}

	// The accepted payload lengths are the reference's; Reticulum-Go
	// has no length rule on the link request path outside
	// Link.HandleLinkRequest, which needs a live destination and a
	// transport. What it does have is the truncation in
	// LinkIDFromLinkRequest, which is the derivation and not a check,
	// so a request of any length yields a link id here.
	if len(p.Data) != ecPubSize && len(p.Data) != ecPubSize+signalSize {
		invalid("invalid-length",
			num("payload_length", len(p.Data)),
			num("accepted_length", ecPubSize),
			num("signalled_length", ecPubSize+signalSize))
		return
	}

	var signalling []byte
	if len(p.Data) == ecPubSize+signalSize {
		signalling = p.Data[ecPubSize:]
	}

	printHeader(p, raw)
	f("x25519_public", hx(p.Data[:32]))
	f("ed25519_public", hx(p.Data[32:ecPubSize]))
	printSignalling(signalling)
	f("link_id", hx(packet.LinkIDFromLinkRequest(p)))
}

func doLinkProof(b [][]byte) {
	requestRaw, identityPublic, raw := b[0], b[1], b[2]

	f("link_request", hx(requestRaw))
	f("signer_public", hx(identityPublic))

	p := unpack(raw)
	if p == nil {
		return
	}

	id, _ := linkID(requestRaw)
	if id == nil {
		panic("the link request does not decode")
	}

	accepted := sigLen + 32
	signalled := len(p.Data) == accepted+signalSize
	if len(p.Data) != accepted && !signalled {
		invalid("invalid-length",
			num("payload_length", len(p.Data)),
			num("accepted_length", accepted),
			num("signalled_length", accepted+signalSize))
		return
	}

	sig := p.Data[:sigLen]
	x25519Public := p.Data[sigLen : sigLen+32]
	var signalling []byte
	if signalled {
		signalling = p.Data[sigLen+32:]
	}
	signerEd := identityPublic[32:]

	// Follows pkg/link/link.go:3523 ValidateLinkProof, which drives a
	// state machine and returns an error; the material is assembled
	// here and handed to Reticulum-Go's own Identity.Verify.
	signed := append([]byte{}, id...)
	signed = append(signed, x25519Public...)
	signed = append(signed, signerEd...)
	signed = append(signed, signalling...)

	signer := identity.FromPublicKey(identityPublic)
	if signer == nil {
		panic("signer public key refused")
	}

	printHeader(p, raw)
	f("link_id", hx(id))
	f("link_id_match", yesNo(bytes.Equal(p.DestinationHash, id)))
	f("signature", hx(sig))
	f("x25519_public", hx(x25519Public))
	printSignalling(signalling)
	f("signer_ed25519", hx(signerEd))
	f("signed_data", hx(signed))
	f("signature_valid", yesNo(signer.Verify(signed, sig)))
}

func doLinkData(b [][]byte) {
	requestRaw, responderPrivate, raw := b[0], b[1], b[2]

	f("link_request", hx(requestRaw))
	f("responder_private", hx(responderPrivate))

	p := unpack(raw)
	if p == nil {
		return
	}

	id, request := linkID(requestRaw)
	if id == nil {
		panic("the link request does not decode")
	}

	printHeader(p, raw)
	f("link_id", hx(id))
	f("link_id_match", yesNo(bytes.Equal(p.DestinationHash, id)))

	// A resource part is not encrypted by the packet layer: the
	// resource encrypted the whole stream through the link and cut the
	// token into parts. A keepalive carries one byte and no token.
	if p.Context == packet.ContextResource || p.Context == packet.ContextKeepalive {
		f("encrypted", "no")
		f("plaintext_length", d(len(p.Data)))
		f("plaintext", hx(p.Data))
		return
	}
	f("encrypted", "yes")

	// decryptWithKeys at pkg/link/link.go:2283 refuses a payload
	// shorter than an iv, one block and an hmac. It is unexported and
	// reached only through a live Link, so the rule is followed here
	// and its threshold printed rather than the reference's. This is
	// the one length rule of its kind in the seven implementations
	// measured; see ../../CONFORMANCE.
	if len(p.Data) < linkTokenMin {
		invalid("short-payload", num("payload_length", len(p.Data)),
			num("minimum_length", linkTokenMin))
		return
	}

	iv := p.Data[:16]
	ct := p.Data[16 : len(p.Data)-32]
	mac := p.Data[len(p.Data)-32:]

	shared, err := cryptography.DeriveSharedSecret(responderPrivate, request.Data[:32])
	if err != nil {
		panic(err)
	}

	// The salt is the link id and the context empty, and 64 bytes are
	// derived for AES-256, as pkg/link/link.go:3284 does.
	derived, err := cryptography.DeriveKey(shared, id, nil, 64)
	if err != nil {
		panic(err)
	}
	signing, encryption := derived[:32], derived[32:]

	macOK := cryptography.ValidateHMAC(signing, p.Data[:len(p.Data)-32], mac)
	var plaintext []byte
	if macOK {
		plaintext, err = cryptography.DecryptAES256CBC(encryption, p.Data[:len(p.Data)-32])
		if err != nil {
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
	f("plaintext_length", d(len(plaintext)))
	f("plaintext", hx(plaintext))

	linkPayload(p.Context, id, plaintext)
}

// linkPayload prints what the context byte names, where Reticulum-Go
// has a decoder for it. Every field it cannot produce is "-".
func linkPayload(context byte, id, plaintext []byte) {
	switch context {
	case packet.ContextChannel:
		// Channel.HandleInbound at pkg/channel/channel.go:297 refuses
		// a payload shorter than ChannelHeaderSize and then reads the
		// three fields at fixed offsets. It is followed rather than
		// called because a Channel wants a live link, and with it the
		// whole interface stack; channelHeaderSize below is its own
		// constant, pkg/channel/constants.go:36.
		if len(plaintext) < channelHeaderSize {
			invalid("short-plaintext", num("minimum_length", channelHeaderSize))
			return
		}
		f("msgtype", hx(plaintext[0:2]))
		f("sequence", d(int(binary.BigEndian.Uint16(plaintext[2:4]))))
		f("declared_length", d(int(binary.BigEndian.Uint16(plaintext[4:6]))))
		f("message", hx(plaintext[6:]))

	case packet.ContextResourceAdv:
		// Reticulum-Go's own advertisement decoder,
		// pkg/resource/advertisement.go:123.
		adv, err := resource.UnpackResourceAdvertisement(plaintext)
		if err != nil {
			for _, n := range []string{"transfer_size", "data_size", "resource_parts",
				"resource_hash", "resource_random", "original_hash", "segment_index",
				"total_segments", "request_id", "resource_flags", "hashmap"} {
				f(n, "-")
			}
			return
		}
		f("transfer_size", d(int(adv.TransferSize)))
		f("data_size", d(int(adv.DataSize)))
		f("resource_parts", d(adv.Parts))
		f("resource_hash", hx(adv.Hash))
		f("resource_random", hx(adv.RandomHash))
		f("original_hash", hx(adv.OriginalHash))
		f("segment_index", d(int(adv.SegmentIndex)))
		f("total_segments", d(int(adv.TotalSegments)))
		f("request_id", hx(adv.RequestID))
		f("resource_flags", fmt.Sprintf("%02x", adv.Flags))
		f("hashmap", hx(adv.Hashmap))

	case packet.ContextResourceReq:
		// Reticulum-Go is the first implementation measured here with
		// a part request decoder: dispatchOutgoingResourceRequests at
		// pkg/link/link.go:1480 reads the flag, the anchor hash, the
		// resource hash and the map hashes, and bounds every one of
		// them by the plaintext. It wants a live outgoing resource to
		// dispatch to, so the reads are followed here. The flag is
		// LinkResourceMappedFlag, 0xff at pkg/link/constants.go:69,
		// and MapHashLen is resource's own.
		if len(plaintext) < 1+32 {
			invalid("short-plaintext", num("minimum_length", 1+32))
			return
		}
		exhausted := plaintext[0] == resourceMappedFlag
		pad := 1
		var lastMapHash []byte
		if exhausted {
			pad = 1 + resource.MapHashLen
			if len(plaintext) < pad+32 {
				invalid("short-plaintext", num("minimum_length", pad+32))
				return
			}
			lastMapHash = plaintext[1:pad]
		}
		f("hashmap_exhausted", yesNo(exhausted))
		f("last_map_hash", hx(lastMapHash))
		f("resource_hash", hx(plaintext[pad:pad+32]))
		f("requested_hashes", hx(plaintext[pad+32:]))

	case packet.ContextResourceHMU:
		// handleResourceHashmapUpdate at pkg/link/link.go:1791: the
		// hash is raw, the two behind it are msgpack, and a plaintext
		// shorter than the hash goes to the started callback instead.
		if len(plaintext) < 32 {
			invalid("short-plaintext", num("minimum_length", 32))
			return
		}
		f("resource_hash", hx(plaintext[:32]))
		var update []any
		if err := msgpack.Unmarshal(plaintext[32:], &update); err != nil || len(update) < 2 {
			f("segment_index", "-")
			f("hashmap", "-")
			return
		}
		f("segment_index", d(wireInt(update[0])))
		hm, _ := update[1].([]byte)
		f("hashmap", hx(hm))

	case packet.ContextResourceICL, packet.ContextResourceRCL:
		// handleResourceCancel and handleResourceReject, at
		// pkg/link/link.go:1844 and :1858, both take the first 32
		// bytes as the resource hash and both bound the read.
		if len(plaintext) < 32 {
			f("resource_hash", "-")
			return
		}
		f("resource_hash", hx(plaintext[:32]))

	case packet.ContextRequest, packet.ContextResponse:
		// Reticulum-Go's own msgpack, as pkg/link/link.go reads a
		// request and a response. The request time comes back as a
		// float64 and is printed as the eight bytes it was decoded
		// from.
		var unpacked []any
		if err := msgpack.Unmarshal(plaintext, &unpacked); err != nil {
			if context == packet.ContextRequest {
				f("request_time", "-")
				f("request_path_hash", "-")
				f("request_data", "-")
			} else {
				f("request_id", "-")
				f("response_data", "-")
			}
			return
		}
		if context == packet.ContextRequest {
			at := make([]byte, 8)
			binary.BigEndian.PutUint64(at, math.Float64bits(toFloat(unpacked[0])))
			f("request_time", hx(at))
			f("request_path_hash", mpBin(unpacked[1]))
			f("request_data", mpBin(unpacked[2]))
		} else {
			f("request_id", mpBin(unpacked[0]))
			f("response_data", mpBin(unpacked[1]))
		}

	case packet.ContextLinkIdentify:
		if len(plaintext) != keySize+sigLen {
			f("identity_public", "-")
			f("identity_hash", "-")
			f("identity_signed", "-")
			f("identity_valid", "-")
			return
		}
		pub := plaintext[:keySize]
		sig := plaintext[keySize:]
		signed := append(append([]byte{}, id...), pub...)
		peer := identity.FromPublicKey(pub)
		if peer == nil {
			panic("identify public key refused")
		}
		f("identity_public", hx(pub))
		f("identity_hash", hx(identity.TruncatedHash(pub)))
		f("identity_signed", hx(signed))
		f("identity_valid", yesNo(peer.Verify(signed, sig)))
	}
}

// The msgpack decoder returns the narrowest type the wire allowed, so a
// segment index comes back as any of these. wireInt at
// pkg/link/incoming_resource.go:1204 is Reticulum-Go's own widening and
// is unexported.
func wireInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int8:
		return int(x)
	case int16:
		return int(x)
	case int32:
		return int(x)
	case int64:
		return int(x)
	case uint8:
		return int(x)
	case uint16:
		return int(x)
	case uint32:
		return int(x)
	case uint64:
		return int(x)
	}
	return 0
}

func toFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int64:
		return float64(n)
	case int:
		return float64(n)
	case uint64:
		return float64(n)
	}
	return 0
}

func mpBin(v any) string {
	switch s := v.(type) {
	case []byte:
		return hx(s)
	case string:
		return hx([]byte(s))
	}
	return "-"
}

// -------------------------------------------------------------------- ifac

// The interface access code is the one kind no harness has been able to
// run: the six implementations measured before this one keep their IFAC
// code inside an interface. Reticulum-Go's pkg/ifac is a package of its
// own with New, Key, Size, Unmask and Sign all exported.
func doIfac(b [][]byte) {
	netname, netkey, sizeBytes, frame := b[0], b[1], b[2], b[3]

	f("netname", hx(netname))
	f("netkey", hx(netkey))

	// The origin is the concatenation of the two hashes, hashed; New
	// at pkg/ifac/ifac.go:84 builds it and keeps neither, so the four
	// lines that build it are followed here with its own hash.
	var origin []byte
	if len(netname) > 0 {
		origin = append(origin, cryptography.Hash(netname)...)
	}
	if len(netkey) > 0 {
		origin = append(origin, cryptography.Hash(netkey)...)
	}

	size := int(sizeBytes[0])
	id, err := ifac.New(size, string(netname), string(netkey))
	if err != nil {
		panic(err)
	}

	f("ifac_origin", hx(origin))
	f("ifac_key", hx(id.Key()))
	f("ifac_size", d(id.Size()))
	f("frame_length", d(len(frame)))

	if len(frame) <= 2+size {
		f("ifac", "-")
		f("packet", "-")
		f("expected_ifac", "-")
		f("ifac_valid", "no")
		return
	}
	f("ifac", hx(frame[2:2+size]))

	// Unmask rebuilds the packet, recomputes the code over it and
	// compares; it reports one boolean for both, so the code is signed
	// again here to print what was expected.
	unmasked, ok, err := id.Unmask(frame)
	if err != nil {
		panic(err)
	}
	f("packet", hx(unmasked))
	if unmasked == nil {
		f("expected_ifac", "-")
		f("ifac_valid", "no")
		return
	}
	expected, err := id.Sign(unmasked)
	if err != nil {
		panic(err)
	}
	f("expected_ifac", hx(expected))
	f("ifac_valid", yesNo(ok))
}

// -------------------------------------------------------------------- main

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: q4ret kind rawfile")
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
		doIdentity(blobs)
	case "keyset":
		doKeyset(blobs)
	case "destination":
		doDestination(blobs)
	case "signature":
		doSignature(blobs)
	case "sign":
		doSign(blobs)
	case "announce":
		doAnnounce(blobs)
	case "encrypted":
		doEncrypted(blobs)
	case "linkrequest":
		doLinkRequest(blobs)
	case "linkproof":
		doLinkProof(blobs)
	case "linkdata":
		doLinkData(blobs)
	case "proof":
		doProof(blobs)
	case "ifac":
		doIfac(blobs)
	default:
		// 77 says the kind is not implemented here. cmd/check counts
		// it as skipped rather than failed; see ../README.
		fmt.Fprintln(os.Stderr, "kind not implemented: "+kind)
		os.Exit(77)
	}
	fmt.Print(strings.Join(out, "\n") + "\n")
}
