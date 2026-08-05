// Conformance harness for svanichkin/go-reticulum.
//
// Prints the reticulum-vectors expect format using the rns package's
// own types and derivations.
//
//	goret kind rawfile

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/svanichkin/go-reticulum/rns"
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
	default:
		fmt.Fprintln(os.Stderr, "unknown kind "+kind)
		os.Exit(2)
	}
	fmt.Print(strings.Join(out, "\n") + "\n")
}
