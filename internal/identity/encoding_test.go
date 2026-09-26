package identity_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"testing"

	ageplugin "filippo.io/age/plugin"
	"golang.org/x/crypto/ssh"

	"github.com/untcha/age-plugin-onepassword/internal/identity"
	"github.com/untcha/age-plugin-onepassword/internal/testutil"
)

func TestEncodeDefault(t *testing.T) {
	const want = "AGE-PLUGIN-ONEPASSWORD-10K6MQ2"
	if got := identity.EncodeDefault(); got != want {
		t.Fatalf("EncodeDefault() = %q, want %q", got, want)
	}
	name, data, err := ageplugin.ParseIdentity(want)
	if err != nil || name != identity.PluginName {
		t.Fatalf("ParseIdentity = %q, %v", name, err)
	}
	pin, err := identity.DecodePayload(data)
	if err != nil || pin != nil {
		t.Fatalf("DecodePayload(default) = %v, %v; want nil, nil", pin, err)
	}
}

func TestPinnedRoundTrip(t *testing.T) {
	for _, k := range []testutil.Key{testutil.Ed25519(t), testutil.RSA(t)} {
		in := identity.Pin{VaultID: "vault1", ItemID: "item1", PubKey: k.PublicKey}
		s, err := identity.EncodePinned(in)
		if err != nil {
			t.Fatal(err)
		}
		_, data, err := ageplugin.ParseIdentity(s)
		if err != nil {
			t.Fatal(err)
		}
		out, err := identity.DecodePayload(data)
		if err != nil {
			t.Fatal(err)
		}
		if out.VaultID != in.VaultID || out.ItemID != in.ItemID ||
			!bytes.Equal(out.PubKey.Marshal(), in.PubKey.Marshal()) {
			t.Fatalf("round trip = %+v, want %+v", out, in)
		}
	}
}

func TestEncodePinnedRejectsInvalid(t *testing.T) {
	pub := testutil.Ed25519(t).PublicKey
	tests := map[string]identity.Pin{
		"empty vault ID":    {VaultID: "", ItemID: "i", PubKey: pub},
		"slash in item ID":  {VaultID: "v", ItemID: "a/b", PubKey: pub},
		"missing publickey": {VaultID: "v", ItemID: "i"},
	}
	for name, p := range tests {
		if _, err := identity.EncodePinned(p); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestDecodePayloadErrors(t *testing.T) {
	pub := testutil.Ed25519(t).PublicKey.Marshal()
	tests := []struct {
		name string
		data []byte
	}{
		{"unknown version", payload(2, []byte("v"), []byte("i"), pub)},
		{"missing fields", payload(1, []byte("v"))},
		{"truncated length", []byte{1, 0}},
		{"truncated field", []byte{1, 0, 5, 'a'}},
		{"empty field", payload(1, []byte{}, []byte("i"), pub)},
		{"trailing bytes", append(payload(1, []byte("v"), []byte("i"), pub), 0xff)},
		{"invalid vault ID", payload(1, []byte("../x"), []byte("i"), pub)},
		{"oversized item ID", payload(1, []byte("v"), bytes.Repeat([]byte("a"), 300), pub)},
		{"garbage public key", payload(1, []byte("v"), []byte("i"), []byte("nope"))},
		{"unsupported key type", payload(1, []byte("v"), []byte("i"), ecdsaPub(t))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := identity.DecodePayload(tt.data); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// payload builds a raw pinned payload: version, then uint16-length-prefixed fields.
func payload(version byte, fields ...[]byte) []byte {
	out := []byte{version}
	for _, f := range fields {
		out = binary.BigEndian.AppendUint16(out, uint16(len(f))) //nolint:gosec // G115: test fields are < 64 KiB.
		out = append(out, f...)
	}
	return out
}

func ecdsaPub(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pub.Marshal()
}
